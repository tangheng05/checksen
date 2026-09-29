use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use checksen::analyzers::Signal;
use checksen::analyzers::llm::{
    self, Classifier, anthropic::AnthropicClassifier, gemini::GeminiClassifier,
};
use checksen::analyzers::text::{self, RULES_VERSION};
use checksen::verdict::{Level, decide};
use serde::{Deserialize, Serialize};
use serde_json::json;

const DATASETS: [&str; 2] = ["v0", "v1"];
const BASELINE: &str = "evals/baseline.json";

#[derive(Deserialize)]
struct Example {
    id: String,
    text: String,
    category: String,
    label: String,
    split: String,
    #[serde(default)]
    verbatim: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct Baseline {
    recall: f64,
    false_positive_rate: f64,
}

#[derive(Default)]
struct Tally {
    scams: usize,
    caught: usize,
    legit: usize,
    false_alarms: usize,
}

impl Tally {
    fn add(&mut self, is_scam: bool, flagged: bool) {
        if is_scam {
            self.scams += 1;
            self.caught += usize::from(flagged);
        } else {
            self.legit += 1;
            self.false_alarms += usize::from(flagged);
        }
    }

    fn recall(&self) -> f64 {
        ratio(self.caught, self.scams)
    }

    fn false_positive_rate(&self) -> f64 {
        ratio(self.false_alarms, self.legit)
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "scams": self.scams,
            "caught": self.caught,
            "legit": self.legit,
            "false_alarms": self.false_alarms,
            "recall": self.recall(),
            "false_positive_rate": self.false_positive_rate(),
        })
    }
}

fn ratio(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    dotenvy::dotenv().ok();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let args: Vec<String> = std::env::args().collect();
    let update_baseline = args.iter().any(|arg| arg == "--update-baseline");

    if let Some(provider) = args
        .iter()
        .position(|arg| arg == "--llm")
        .map(|at| args.get(at + 1))
    {
        let timeout = Duration::from_secs(120);
        let classifier: Box<dyn Classifier> = match provider.map(String::as_str) {
            Some("gemini") => {
                Box::new(GeminiClassifier::from_env(timeout, 8)?.context("set GEMINI_API_KEY")?)
            }
            Some("claude") => Box::new(
                AnthropicClassifier::from_env(timeout, 8)?.context("set ANTHROPIC_API_KEY")?,
            ),
            _ => bail!("usage: eval --llm gemini|claude"),
        };
        let provider = provider.map(String::as_str).unwrap_or_default();
        evaluate(root, "v1", Some((provider, classifier.as_ref()))).await?;
        return Ok(ExitCode::SUCCESS);
    }

    let mut current = BTreeMap::new();
    for name in DATASETS {
        current.insert(name.to_owned(), evaluate(root, name, None).await?);
    }

    if update_baseline {
        fs::write(
            root.join(BASELINE),
            serde_json::to_string_pretty(&current)? + "\n",
        )?;
        println!("baseline updated");
        return Ok(ExitCode::SUCCESS);
    }

    let baselines: BTreeMap<String, Baseline> = serde_json::from_str(
        &fs::read_to_string(root.join(BASELINE))
            .context("no baseline yet; run with --update-baseline")?,
    )?;
    let mut worse = false;
    for (name, now) in &current {
        let Some(baseline) = baselines.get(name) else {
            eprintln!("{name}: no baseline; run with --update-baseline");
            worse = true;
            continue;
        };
        let recall_dropped = now.recall + f64::EPSILON < baseline.recall;
        let false_positives_rose =
            now.false_positive_rate > baseline.false_positive_rate + f64::EPSILON;
        if recall_dropped || false_positives_rose {
            eprintln!(
                "{name} worse than baseline: recall {:.3} (baseline {:.3}), false positives {:.3} (baseline {:.3})",
                now.recall, baseline.recall, now.false_positive_rate, baseline.false_positive_rate,
            );
            worse = true;
        }
    }
    Ok(if worse {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

async fn evaluate(
    root: &Path,
    name: &str,
    model: Option<(&str, &dyn Classifier)>,
) -> anyhow::Result<Baseline> {
    let variant = match model {
        Some((provider, _)) => format!("rules-v{RULES_VERSION}+{provider}"),
        None => format!("rules-v{RULES_VERSION}"),
    };
    let path = format!("evals/data/{name}.jsonl");
    let dataset =
        fs::read_to_string(root.join(&path)).with_context(|| format!("reading {path}"))?;
    let examples: Vec<Example> = dataset
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).with_context(|| format!("{path} line {}", index + 1))
        })
        .collect::<anyhow::Result<_>>()?;

    let mut splits: BTreeMap<&str, Tally> = BTreeMap::new();
    let mut strata: BTreeMap<&str, Tally> = BTreeMap::new();
    let mut categories: BTreeMap<&str, Tally> = BTreeMap::new();
    let mut total = Tally::default();
    let mut model_errors = 0;
    let mut missed = Vec::new();
    let mut false_alarms = Vec::new();

    for example in &examples {
        let is_scam = example.label == "scam";
        let mut check = text::check(&example.text);
        if let Some((_, classifier)) = model {
            check = llm::classify(check, &example.text, classifier, Duration::from_secs(300)).await;
            model_errors += usize::from(check.signals.contains(&Signal::ModelUnavailable));
            eprint!(".");
        }
        let level = decide(&check);
        let flagged = matches!(level, Level::HighRisk | Level::Suspicious);

        total.add(is_scam, flagged);
        splits
            .entry(&example.split)
            .or_default()
            .add(is_scam, flagged);
        if let Some(verbatim) = example.verbatim {
            let stratum = if verbatim {
                "verbatim"
            } else {
                "reconstructed"
            };
            strata.entry(stratum).or_default().add(is_scam, flagged);
        }
        categories
            .entry(&example.category)
            .or_default()
            .add(is_scam, flagged);
        if is_scam && !flagged {
            missed.push(example.id.as_str());
        }
        if !is_scam && flagged {
            false_alarms.push(example.id.as_str());
        }
    }

    if model.is_some() {
        eprintln!();
    }
    println!("{name}: {variant} on {} examples", examples.len());
    if model.is_some() {
        println!("  model errors (fell back to rules): {model_errors}");
    }
    for (group, tally) in splits
        .iter()
        .chain(&strata)
        .map(|(group, tally)| (*group, tally))
        .chain([("all", &total)])
    {
        println!(
            "  {group:<13} recall {:>5.1}% ({}/{})   false positives {:>5.1}% ({}/{})",
            tally.recall() * 100.0,
            tally.caught,
            tally.scams,
            tally.false_positive_rate() * 100.0,
            tally.false_alarms,
            tally.legit,
        );
    }
    println!("  missed: {}", missed.join(", "));
    println!("  false alarms: {}", false_alarms.join(", "));

    let to_json = |tallies: &BTreeMap<&str, Tally>| {
        tallies
            .iter()
            .map(|(group, tally)| (group.to_string(), tally.to_json()))
            .collect::<BTreeMap<_, _>>()
    };
    let report = json!({
        "rules_version": RULES_VERSION,
        "variant": variant,
        "model_errors": model_errors,
        "dataset": path,
        "examples": examples.len(),
        "all": total.to_json(),
        "splits": to_json(&splits),
        "strata": to_json(&strata),
        "categories": to_json(&categories),
        "missed": missed,
        "false_alarms": false_alarms,
    });
    let report_path: PathBuf = root.join(format!("evals/results/{variant}-{name}.json"));
    fs::write(&report_path, serde_json::to_string_pretty(&report)? + "\n")?;

    Ok(Baseline {
        recall: total.recall(),
        false_positive_rate: total.false_positive_rate(),
    })
}
