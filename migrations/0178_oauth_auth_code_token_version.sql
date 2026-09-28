-- Authorization codes carry the account generation they were issued under.
--
-- A grant already stores token_version and fails when it no longer matches
-- users.token_version. A code did not, so exchanging one after a sign-out,
-- password change, reset, or seizure read the new generation and minted a grant
-- that passed the check. The default of 0 is only for rows that exist when this
-- column appears: users.token_version starts at 1, so those codes match nothing.
-- New codes set the generation explicitly, and the default is dropped so an
-- insert that forgets it fails instead of storing 0.

ALTER TABLE oauth_auth_codes
    -- squawk-ignore prefer-bigint-over-int -- same width as users.token_version and oauth_grants.token_version, both integer; a bigint here would disagree with the generation it is compared against, and a session generation does not approach the int32 ceiling
    ADD COLUMN token_version integer NOT NULL DEFAULT 0;

ALTER TABLE oauth_auth_codes
    ALTER COLUMN token_version DROP DEFAULT;
