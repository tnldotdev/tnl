package state

import (
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func ingressPortRanges(ranges []tcpport.Range) (pgtype.Multirange[pgtype.Range[pgtype.Int4]], error) {
	inventory, err := tcpport.NewInventory(ranges)
	if err != nil {
		return nil, err
	}
	canonical := inventory.Ranges()
	result := make(pgtype.Multirange[pgtype.Range[pgtype.Int4]], len(canonical))
	for index, r := range canonical {
		result[index] = pgtype.Range[pgtype.Int4]{
			Lower:     pgtype.Int4{Int32: int32(r.First), Valid: true},
			Upper:     pgtype.Int4{Int32: int32(r.Last + 1), Valid: true},
			LowerType: pgtype.Inclusive, UpperType: pgtype.Exclusive, Valid: true,
		}
	}
	return result, nil
}

func ingressPortInventory(ranges pgtype.Multirange[pgtype.Range[pgtype.Int4]]) (tcpport.Inventory, error) {
	values := make([]tcpport.Range, len(ranges))
	for index, r := range ranges {
		// the schema limits postgres's canonical [first, last+1) ranges to finite bounds.
		if !r.Valid || !r.Lower.Valid || !r.Upper.Valid || r.LowerType != pgtype.Inclusive || r.UpperType != pgtype.Exclusive {
			return tcpport.Inventory{}, tcpport.ErrInventory
		}
		values[index] = tcpport.Range{First: int(r.Lower.Int32), Last: int(r.Upper.Int32) - 1}
	}
	return tcpport.NewInventory(values)
}
