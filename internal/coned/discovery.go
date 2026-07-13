package coned

import (
	"context"
	"strconv"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/provider"
)

func (c *Client) Discover(ctx context.Context, session auth.Session) ([]provider.Entity, error) {
	d, err := c.callMap(ctx, session, "WBAS_BillingAccounts", accountsQuery, map[string]any{"first": 100, "onlyActive": true})
	if err != nil {
		return nil, err
	}
	var out []provider.Entity
	for _, edge := range edges(d, "billingAccountsConnection") {
		node := field(obj(edge), "node")
		accountID := text(node["urn"])
		if accountID == "" {
			accountID = text(node["uuid"])
		}
		if accountID == "" {
			continue
		}
		out = append(out, provider.Entity{Type: "account", ProviderID: accountID, Active: true, Provenance: "coned-live-verified"})
		metadata, e := c.callMap(ctx, session, "WRTAMI_GetMetadata", meterMetadataQuery, map[string]any{"selectedAccount": accountID, "forceLegacyData": false})
		if e != nil {
			continue
		}
		for _, saEdge := range edges(field(metadata, "billingAccountByAuthContext"), "serviceAgreementsConnection") {
			sa := field(obj(saEdge), "node")
			service := text(sa["serviceType"])
			for _, spEdge := range edges(sa, "servicePointsConnection") {
				sp := field(obj(spEdge), "node")
				spID := text(sp["uuid"])
				if spID == "" {
					continue
				}
				premiseID := text(field(sp, "premise")["uuid"])
				if premiseID != "" {
					out = appendUniqueEntity(out, provider.Entity{Type: "premise", ProviderID: premiseID, ParentProviderID: accountID, Active: true, Provenance: "coned-live-verified"})
				}
				out = append(out, provider.Entity{Type: "meter", ProviderID: spID, ParentProviderID: accountID, ServiceType: service, Active: true, Provenance: "coned-live-verified"})
				for i, raw := range arr(sp["registers"]) {
					r := obj(raw)
					rid := text(r["serviceQuantityIdentifier"])
					if rid == "" {
						rid = spID + "#" + strconv.Itoa(i)
					}
					out = append(out, provider.Entity{Type: "register", ProviderID: rid, ParentProviderID: spID, ServiceType: service, ReadResolution: text(r["readResolution"]), Unit: text(r["unitOfMeasure"]), Active: true, Provenance: "coned-live-verified"})
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrProtocolChanged
	}
	for i := range out {
		out[i].ContractVersion = 1
		out[i].LastVerified = "2026-07-12"
	}
	return out, nil
}
func appendUniqueEntity(items []provider.Entity, item provider.Entity) []provider.Entity {
	for _, existing := range items {
		if existing.Type == item.Type && existing.ProviderID == item.ProviderID {
			return items
		}
	}
	return append(items, item)
}
