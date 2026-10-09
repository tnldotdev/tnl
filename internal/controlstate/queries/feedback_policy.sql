-- guest trials have a saved ownership boundary without a local team policy.
-- only known guest teams default to optional sign-in; missing teams fail closed.
-- name: GetReviewerFeedbackPolicy :one
SELECT team.feedback_require_sign_in
FROM control.teams AS team
WHERE team.id = sqlc.arg(team_id) AND team.deleted_at IS NULL
UNION ALL
SELECT false AS feedback_require_sign_in
FROM control.guest_trials AS guest
WHERE guest.team_id = sqlc.arg(team_id)
  AND NOT EXISTS (SELECT 1 FROM control.teams AS local_team WHERE local_team.id = guest.team_id);

-- name: GetIdentityTeamFeedbackPolicy :one
SELECT t.feedback_require_sign_in
FROM control.teams AS t
JOIN control.team_memberships AS m
  ON m.team_id = t.id AND m.identity_id = sqlc.arg(identity_id)
 AND m.removed_at IS NULL
JOIN control.identities AS i ON i.id = m.identity_id AND i.disabled_at IS NULL
WHERE t.id = sqlc.arg(team_id) AND t.deleted_at IS NULL;

-- name: SetTeamFeedbackPolicy :one
UPDATE control.teams
SET feedback_require_sign_in = sqlc.arg(require_sign_in), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(team_id) AND deleted_at IS NULL
RETURNING feedback_require_sign_in;
