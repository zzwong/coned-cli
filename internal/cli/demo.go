package cli

import (
	"context"
	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
)

type demoOpower struct{}

func (demoOpower) Fetch(_ context.Context, _ auth.Session, resource string) (any, error) {
	switch resource {
	case "accounts":
		return []coned.Account{{ID: "account-demo0001", Name: "Sample Home", UtilityCode: "CNED", CustomerClass: "RESIDENTIAL", ServiceAgreementCount: 2}}, nil
	case "usage-bills", "export":
		return []coned.UsageBill{{Start: "2026-01-01", End: "2026-02-01", Usage: coned.Quantity{Unit: "KWH", Value: 420}, Charges: 120}, {Start: "2026-02-01", End: "2026-03-01", Estimated: true, Usage: coned.Quantity{Unit: "KWH", Value: 390}, Charges: 115}}, nil
	case "weather":
		return []coned.Weather{{Start: "2026-01-01", End: "2026-02-01", Minimum: 20, Mean: 35, Maximum: 55}}, nil
	case "neighbors":
		return []coned.NeighborComparison{{MeterType: "ELECTRIC", Start: "2026-01-01", End: "2026-02-01", You: coned.Quantity{Unit: "KWH", Value: 420}, EfficientNeighbors: coned.Quantity{Unit: "KWH", Value: 250}, AllNeighbors: coned.Quantity{Unit: "KWH", Value: 380}, NeighborCount: 100}}, nil
	case "meters":
		return []coned.Meter{{ID: "meter-demo0001", ServiceType: "ELECTRIC", ReadResolution: "HOUR", Unit: "KWH", AvailableStart: "2025-01-01", AvailableEnd: "2026-07-01"}}, nil
	case "realtime":
		return []coned.UsageRead{{Start: "2026-07-01T00:00:00-04:00", End: "2026-07-01T00:15:00-04:00", Unit: "KWH", Value: .2}}, nil
	case "summary":
		return coned.UsageSummary{Bills: 2, Usage: coned.Quantity{Unit: "KWH", Value: 810}, Charges: 235}, nil
	default:
		return nil, coned.ErrProtocolChanged
	}
}
func (demoOpower) FetchSelected(ctx context.Context, s auth.Session, r string, _ coned.EntitySelection) (any, error) {
	return demoOpower{}.Fetch(ctx, s, r)
}
func (demoOpower) Forecast(context.Context, auth.Session) ([]coned.Forecast, error) {
	return []coned.Forecast{{Account: "account-demo0001", Start: "2026-07-01", End: "2026-08-01", Current: "2026-07-12", Unit: "KWH", UsageToDate: 150, CostToDate: 45, ForecastUsage: 410, ForecastCost: 125, TypicalUsage: 390, TypicalCost: 118}}, nil
}
func (demoOpower) HistoricalReads(_ context.Context, _ auth.Session, o coned.ReadOptions) ([]coned.HistoricalRead, error) {
	return []coned.HistoricalRead{{Account: "account-demo0001", Start: demoStart(o), End: demoEnd(o), Value: 1.25}}, nil
}
func (demoOpower) HistoricalCosts(_ context.Context, _ auth.Session, o coned.ReadOptions) ([]coned.CostRead, error) {
	return []coned.CostRead{{Account: "account-demo0001", Start: demoStart(o), End: demoEnd(o), Value: 1.25, Cost: .42}}, nil
}
func demoStart(o coned.ReadOptions) string {
	if o.From != "" {
		return o.From
	}
	return "2026-01-01"
}
func demoEnd(o coned.ReadOptions) string {
	if o.To != "" {
		return o.To
	}
	return "2026-02-01"
}
