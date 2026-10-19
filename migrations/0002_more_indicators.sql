ALTER TABLE indicators DROP CONSTRAINT indicators_kind_check;
ALTER TABLE indicators ADD CONSTRAINT indicators_kind_check
    CHECK (kind IN ('khqr_account', 'phone', 'telegram_username', 'domain'));
