-- name: OpenServiceRecoveryEpisode :exec
INSERT INTO control.service_recovery_episodes(service_id,service_run_id,run_number,state,opened_at)
VALUES(sqlc.arg(service_id),sqlc.arg(service_run_id),sqlc.arg(run_number),'open',sqlc.arg(opened_at))
ON CONFLICT(service_run_id) WHERE state='open' DO NOTHING;

-- name: GetOpenServiceRecoveryEpisode :one
SELECT * FROM control.service_recovery_episodes
WHERE service_run_id=$1 AND state='open';

-- name: CancelOpenServiceRecoveryEpisode :exec
UPDATE control.service_recovery_episodes SET state='canceled',canceled_at=sqlc.arg(canceled_at)
WHERE service_run_id=sqlc.arg(service_run_id) AND state='open';

-- name: LockServiceRecoveryEpisode :one
SELECT * FROM control.service_recovery_episodes WHERE id=$1 FOR UPDATE;

-- name: ObserveServiceRecoveryEpisode :one
UPDATE control.service_recovery_episodes
SET state='observed',observed_at=sqlc.arg(observed_at),recovery_seconds=sqlc.arg(observed_seconds)
WHERE id=sqlc.arg(recovery_episode_id) AND state='open' RETURNING *;

-- name: UpdateServiceRecoveryHistogram :exec
UPDATE control.service_recovery_histogram
SET observation_count=observation_count+1,
    observation_sum_seconds=observation_sum_seconds+sqlc.arg(observed_seconds),
    bucket_le_0_25=bucket_le_0_25+CASE WHEN sqlc.arg(observed_seconds)<=0.25 THEN 1 ELSE 0 END,
    bucket_le_0_5=bucket_le_0_5+CASE WHEN sqlc.arg(observed_seconds)<=0.5 THEN 1 ELSE 0 END,
    bucket_le_1=bucket_le_1+CASE WHEN sqlc.arg(observed_seconds)<=1 THEN 1 ELSE 0 END,
    bucket_le_2=bucket_le_2+CASE WHEN sqlc.arg(observed_seconds)<=2 THEN 1 ELSE 0 END,
    bucket_le_5=bucket_le_5+CASE WHEN sqlc.arg(observed_seconds)<=5 THEN 1 ELSE 0 END,
    bucket_le_10=bucket_le_10+CASE WHEN sqlc.arg(observed_seconds)<=10 THEN 1 ELSE 0 END,
    bucket_le_20=bucket_le_20+CASE WHEN sqlc.arg(observed_seconds)<=20 THEN 1 ELSE 0 END,
    bucket_le_30=bucket_le_30+CASE WHEN sqlc.arg(observed_seconds)<=30 THEN 1 ELSE 0 END,
    bucket_le_45=bucket_le_45+CASE WHEN sqlc.arg(observed_seconds)<=45 THEN 1 ELSE 0 END,
    bucket_le_60=bucket_le_60+CASE WHEN sqlc.arg(observed_seconds)<=60 THEN 1 ELSE 0 END,
    bucket_le_120=bucket_le_120+CASE WHEN sqlc.arg(observed_seconds)<=120 THEN 1 ELSE 0 END,
    updated_at=sqlc.arg(updated_at)
WHERE id=1;
