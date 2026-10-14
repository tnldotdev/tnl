-- guest trials have a saved ownership boundary without a local team policy.
-- only known guest teams default to optional sign-in; missing teams fail closed.
-- name: GetReviewerFeedbackPolicy :one
SELECT coalesce(policy.require_sign_in, false) AS require_sign_in
FROM control.teams AS team
LEFT JOIN control.team_feedback_policies AS policy ON policy.team_id = team.id
WHERE team.id = sqlc.arg(team_id) AND team.deleted_at IS NULL
UNION ALL
SELECT false AS require_sign_in
FROM control.guest_trials AS guest
WHERE guest.team_id = sqlc.arg(team_id)
  AND NOT EXISTS (SELECT 1 FROM control.teams AS local_team WHERE local_team.id = guest.team_id);

-- name: GetIdentityTeamFeedbackPolicy :one
SELECT coalesce(policy.require_sign_in, false) AS require_sign_in
FROM control.teams AS t
LEFT JOIN control.team_feedback_policies AS policy ON policy.team_id = t.id
JOIN control.team_memberships AS m
  ON m.team_id = t.id AND m.identity_id = sqlc.arg(identity_id)
 AND m.removed_at IS NULL
JOIN control.identities AS i ON i.id = m.identity_id AND i.disabled_at IS NULL
WHERE t.id = sqlc.arg(team_id) AND t.deleted_at IS NULL;

-- name: SetTeamFeedbackPolicy :one
INSERT INTO control.team_feedback_policies (team_id, require_sign_in)
SELECT id, sqlc.arg(require_sign_in)::boolean
FROM control.teams WHERE id = sqlc.arg(team_id) AND deleted_at IS NULL
ON CONFLICT (team_id) DO UPDATE SET require_sign_in = excluded.require_sign_in
RETURNING require_sign_in;
