package cli

import "github.com/zzwong/coned-cli/internal/coned"

type forecastEnvelopeRow struct {
	Account       string   `json:"account"`
	Start         string   `json:"start"`
	End           string   `json:"end"`
	Current       string   `json:"current"`
	Unit          *string  `json:"unit"`
	UsageToDate   *float64 `json:"usage_to_date"`
	CostToDate    *float64 `json:"cost_to_date"`
	ForecastUsage *float64 `json:"forecast_usage"`
	ForecastCost  *float64 `json:"forecast_cost"`
	TypicalUsage  *float64 `json:"typical_usage"`
	TypicalCost   *float64 `json:"typical_cost"`
	Currency      *string  `json:"currency"`
}

type historicalReadEnvelopeRow struct {
	Account string   `json:"account"`
	Start   string   `json:"start"`
	End     string   `json:"end"`
	Value   *float64 `json:"value"`
	Unit    *string  `json:"unit"`
}

type costEnvelopeRow struct {
	Account  string   `json:"account"`
	Start    string   `json:"start"`
	End      string   `json:"end"`
	Value    *float64 `json:"value"`
	Cost     *float64 `json:"cost"`
	Unit     *string  `json:"unit"`
	Currency *string  `json:"currency"`
}

func forecastEnvelopeData(source []coned.Forecast) []forecastEnvelopeRow {
	out := make([]forecastEnvelopeRow, 0, len(source))
	for _, row := range source {
		out = append(out, forecastEnvelopeRow{
			Account: row.Account, Start: row.Start, End: row.End, Current: row.Current,
			Unit:          optionalString(row.Unit, row.AvailabilityKnown, row.UnitPresent),
			UsageToDate:   optionalNumber(row.UsageToDate, row.AvailabilityKnown, row.UsageToDatePresent),
			CostToDate:    optionalNumber(row.CostToDate, row.AvailabilityKnown, row.CostToDatePresent),
			ForecastUsage: optionalNumber(row.ForecastUsage, row.AvailabilityKnown, row.ForecastUsagePresent),
			ForecastCost:  optionalNumber(row.ForecastCost, row.AvailabilityKnown, row.ForecastCostPresent),
			TypicalUsage:  optionalNumber(row.TypicalUsage, row.AvailabilityKnown, row.TypicalUsagePresent),
			TypicalCost:   optionalNumber(row.TypicalCost, row.AvailabilityKnown, row.TypicalCostPresent),
		})
	}
	return out
}

func historicalReadEnvelopeData(source []coned.HistoricalRead) []historicalReadEnvelopeRow {
	out := make([]historicalReadEnvelopeRow, 0, len(source))
	for _, row := range source {
		out = append(out, historicalReadEnvelopeRow{
			Account: row.Account, Start: row.Start, End: row.End,
			Value: optionalNumber(row.Value, row.AvailabilityKnown, row.ValuePresent),
			Unit:  optionalString(row.Unit, row.AvailabilityKnown, row.UnitPresent),
		})
	}
	return out
}

func costEnvelopeData(source []coned.CostRead) []costEnvelopeRow {
	out := make([]costEnvelopeRow, 0, len(source))
	for _, row := range source {
		out = append(out, costEnvelopeRow{
			Account: row.Account, Start: row.Start, End: row.End,
			Value: optionalNumber(row.Value, row.AvailabilityKnown, row.ValuePresent),
			Cost:  optionalNumber(row.Cost, row.AvailabilityKnown, row.CostPresent),
			Unit:  optionalString(row.Unit, row.AvailabilityKnown, row.UnitPresent),
		})
	}
	return out
}

func optionalNumber(value float64, known, present bool) *float64 {
	if known && !present {
		return nil
	}
	return &value
}

func optionalString(value string, known, present bool) *string {
	if (known && !present) || value == "" {
		return nil
	}
	return &value
}
