package state

const nativePreparationShapeFingerprint = "ad1c6cfb81377f1aa9a2cf460062b42c"

// all three entrypoints use the same catalog fence under the explicit
// intermediate baseline identity. this digest is structural, not a credential.
const schemaIdentityQuery = `SELECT baseline_id FROM control.schema_identity WHERE id=1
    AND md5((` + nativePreparationCatalogSQL + `))='` + nativePreparationShapeFingerprint + `'`

// the intermediate identity is shared with an older incompatible database.
// fingerprint only the native preparation facts owned here, not unrelated
// guest/accounting state. include real definitions, validation and enabled
// enforcement, so a same-named weakened constraint cannot pass the fence.
// changing this catalog requires the coordinated fresh-database cutover.
const nativePreparationCatalogSQL = `SELECT jsonb_build_object(
    'tables',(SELECT jsonb_agg(jsonb_build_array(c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity) ORDER BY c.relname COLLATE "C")
        FROM pg_class c WHERE c.oid IN (to_regclass('control.native_peer_pairs'),to_regclass('control.native_peer_pair_leg_claims'),to_regclass('control.relay_run_signing_keys'))),
    'columns',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,
        pg_get_expr(d.adbin,d.adrelid),coll.collname) ORDER BY c.relname COLLATE "C",a.attname COLLATE "C")
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        LEFT JOIN pg_collation coll ON coll.oid=a.attcollation WHERE a.attnum>0 AND NOT a.attisdropped AND
        (c.oid IN (to_regclass('control.native_peer_pairs'),to_regclass('control.native_peer_pair_leg_claims'),to_regclass('control.relay_run_signing_keys'))
            OR c.oid=to_regclass('control.relay_leases') AND a.attname='peer_signing_public_key')),
    'constraints',(SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,k.contype,k.convalidated,k.condeferrable,k.condeferred,
        pg_get_constraintdef(k.oid)) ORDER BY c.relname COLLATE "C",k.conname COLLATE "C")
        FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE
        c.oid IN (to_regclass('control.native_peer_pairs'),to_regclass('control.native_peer_pair_leg_claims'),to_regclass('control.relay_run_signing_keys'))
        OR c.oid=to_regclass('control.relay_leases') AND k.conkey @> ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=c.oid AND attname='peer_signing_public_key' AND NOT attisdropped)]::smallint[]),
    'indexes',(SELECT jsonb_agg(jsonb_build_array(c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive) ORDER BY c.relname COLLATE "C",pg_get_indexdef(i.indexrelid) COLLATE "C")
        FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.oid IN (to_regclass('control.native_peer_pairs'),to_regclass('control.native_peer_pair_leg_claims'),to_regclass('control.relay_run_signing_keys'))),
    'triggers',(SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,t.tgtype,t.tgenabled,t.tgisinternal,p.proname,
        CASE WHEN NOT t.tgisinternal THEN pg_get_triggerdef(t.oid) END) ORDER BY c.relname COLLATE "C",k.conname COLLATE "C",t.tgtype,p.proname COLLATE "C")
        FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_proc p ON p.oid=t.tgfoid LEFT JOIN pg_constraint k ON k.oid=t.tgconstraint
        WHERE c.oid IN (to_regclass('control.native_peer_pairs'),to_regclass('control.native_peer_pair_leg_claims'),to_regclass('control.relay_run_signing_keys'))
            OR k.conrelid IN (to_regclass('control.native_peer_pairs'),to_regclass('control.native_peer_pair_leg_claims'),to_regclass('control.relay_run_signing_keys'))),
    'sequence',(SELECT jsonb_build_array(c.relkind,s.seqtypid::regtype::text,s.seqstart,s.seqincrement,s.seqmax,s.seqmin,s.seqcache,s.seqcycle)
        FROM pg_class c JOIN pg_sequence s ON s.seqrelid=c.oid WHERE c.oid=to_regclass('control.native_peer_delivery_generation'))
)::text`
