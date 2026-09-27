package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/config"
	"github.com/zzwong/coned-cli/internal/identity"
	"github.com/zzwong/coned-cli/internal/provider"
)

type entityRecord struct {
	Handle          string `json:"handle"`
	Alias           string `json:"alias,omitempty"`
	Type            string `json:"type"`
	Parent          string `json:"parent,omitempty"`
	ServiceType     string `json:"service_type,omitempty"`
	ReadResolution  string `json:"read_resolution,omitempty"`
	Unit            string `json:"unit,omitempty"`
	Active          bool   `json:"active"`
	Selected        bool   `json:"selected,omitempty"`
	Provenance      string `json:"provenance"`
	ContractVersion int    `json:"contract_version"`
	LastVerified    string `json:"last_verified"`
	Demo            bool   `json:"demo,omitempty"`
}

func newEntitiesCommand(options *Options, deps Dependencies) *cobra.Command {
	root := &cobra.Command{Use: "entities", Short: "Discover and select local account and meter identities", Args: cobra.NoArgs}
	var kind string
	list := &cobra.Command{Use: "list", Short: "List privacy-preserving entity handles", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runEntityList(cmd, options, deps, kind) }}
	list.Flags().StringVar(&kind, "type", "", "filter: account, premise, meter, or register")
	root.AddCommand(list)
	root.AddCommand(&cobra.Command{Use: "alias <handle> <alias>", Short: "Assign a local alias", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		return saveEntityAlias(cmd, options, deps, args[0], args[1])
	}})
	root.AddCommand(&cobra.Command{Use: "select <handle-or-alias>", Short: "Set a profile default account or meter", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return selectEntity(cmd, options, deps, args[0]) }})
	return root
}

func entityContext(cmd *cobra.Command, options *Options, deps Dependencies) ([]provider.Entity, *identity.Manager, error) {
	service := deps.Discovery
	var session auth.Session
	if options.Demo {
		service = deps.DemoDiscovery
	} else {
		var err error
		session, err = billingSession(deps, options.Profile)
		if err != nil {
			return nil, nil, err
		}
	}
	if service == nil {
		return nil, nil, coned.ErrProtocolChanged
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
	defer cancel()
	entities, err := service.Discover(ctx, session)
	if err != nil {
		return nil, nil, err
	}
	var manager *identity.Manager
	if options.Demo {
		manager = identity.Deterministic("default")
	} else {
		manager, err = identity.Load(deps.Store, options.Profile, !handlesInUse(deps, options.Profile))
		if err != nil {
			return nil, nil, auth.StorageError(err)
		}
	}
	return entities, manager, nil
}
func runEntityList(cmd *cobra.Command, options *Options, deps Dependencies, kind string) error {
	entities, manager, err := entityContext(cmd, options, deps)
	if err != nil {
		return safeOpowerError(err)
	}
	cfg, _ := config.Load(deps.ConfigPath)
	selection := cfg.Selections[options.Profile]
	handles := map[string]string{}
	for _, entity := range entities {
		h, e := manager.Handle(identity.Entity{Type: entity.Type, Namespace: "coned-opower", ProviderID: entity.ProviderID})
		if e != nil {
			return coned.ErrProtocolChanged
		}
		handles[entity.Type+"\x00"+entity.ProviderID] = h
	}
	aliasByHandle := map[string]string{}
	for alias, handle := range selection.Aliases {
		aliasByHandle[handle] = alias
	}
	var records []entityRecord
	for _, entity := range entities {
		if kind != "" && kind != entity.Type {
			continue
		}
		handle := handles[entity.Type+"\x00"+entity.ProviderID]
		parent := ""
		if entity.ParentProviderID != "" {
			for _, candidate := range entities {
				if candidate.ProviderID == entity.ParentProviderID {
					parent = handles[candidate.Type+"\x00"+candidate.ProviderID]
					break
				}
			}
		}
		selected := handle == selection.DefaultAccount || handle == selection.DefaultMeter
		records = append(records, entityRecord{handle, aliasByHandle[handle], entity.Type, parent, entity.ServiceType, entity.ReadResolution, entity.Unit, entity.Active, selected, entity.Provenance, entity.ContractVersion, entity.LastVerified, options.Demo})
	}
	if options.JSON {
		return writeJSON(cmd.OutOrStdout(), records)
	}
	return writeTable(cmd.OutOrStdout(), records)
}
func saveEntityAlias(cmd *cobra.Command, options *Options, deps Dependencies, handle, alias string) error {
	if options.Demo {
		return errors.New("demo aliases are not persisted")
	}
	if !identity.ValidAlias(alias) || !validEntityHandle(handle) {
		return coned.ErrProtocolChanged
	}
	entities, manager, err := entityContext(cmd, options, deps)
	if err != nil {
		return safeOpowerError(err)
	}
	found := false
	for _, entity := range entities {
		h, _ := manager.Handle(identity.Entity{Type: entity.Type, Namespace: "coned-opower", ProviderID: entity.ProviderID})
		if h == handle {
			found = true
			break
		}
	}
	if !found {
		return coned.ErrSelectionRequired
	}
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return coned.ErrProtocolChanged
	}
	if cfg.Selections == nil {
		cfg.Selections = map[string]config.Selection{}
	}
	selection := cfg.Selections[options.Profile]
	if selection.Aliases == nil {
		selection.Aliases = map[string]string{}
	}
	for existing, h := range selection.Aliases {
		if existing == alias && h != handle {
			return coned.ErrProtocolChanged
		}
	}
	selection.Aliases[alias] = handle
	cfg.Selections[options.Profile] = selection
	if cfg.Save(deps.ConfigPath) != nil {
		return coned.ErrProtocolChanged
	}
	return nil
}
func selectEntity(cmd *cobra.Command, options *Options, deps Dependencies, value string) error {
	if options.Demo {
		return errors.New("demo selections are not persisted")
	}
	entities, manager, err := entityContext(cmd, options, deps)
	if err != nil {
		return safeOpowerError(err)
	}
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return coned.ErrProtocolChanged
	}
	selection := cfg.Selections[options.Profile]
	if h, ok := selection.Aliases[value]; ok {
		value = h
	}
	foundType := ""
	for _, entity := range entities {
		h, _ := manager.Handle(identity.Entity{Type: entity.Type, Namespace: "coned-opower", ProviderID: entity.ProviderID})
		if h == value && entity.Active {
			foundType = entity.Type
			break
		}
	}
	if foundType != "account" && foundType != "meter" {
		return coned.ErrProtocolChanged
	}
	if cfg.Selections == nil {
		cfg.Selections = map[string]config.Selection{}
	}
	if foundType == "account" {
		selection.DefaultAccount = value
	} else {
		selection.DefaultMeter = value
	}
	cfg.Selections[options.Profile] = selection
	if cfg.Save(deps.ConfigPath) != nil {
		return coned.ErrProtocolChanged
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), "selected "+strings.SplitN(value, "-", 2)[0])
	return err
}
func resolveEntitySelection(ctx context.Context, options *Options, deps Dependencies, session auth.Session) (coned.EntitySelection, error) {
	account, meter := options.Account, options.Meter
	var selection config.Selection
	if deps.ConfigPath != "" {
		cfg, err := config.Load(deps.ConfigPath)
		if err != nil {
			return coned.EntitySelection{}, coned.ErrProtocolChanged
		}
		selection = cfg.Selections[options.Profile]
	}
	if h, ok := selection.Aliases[account]; ok {
		account = h
	}
	if h, ok := selection.Aliases[meter]; ok {
		meter = h
	}
	if account == "" {
		account = selection.DefaultAccount
	}
	if meter == "" {
		meter = selection.DefaultMeter
	}
	if account == "" && meter == "" {
		return coned.EntitySelection{}, nil
	}
	if deps.Discovery == nil {
		return coned.EntitySelection{}, coned.ErrSelectionRequired
	}
	entities, err := deps.Discovery.Discover(ctx, session)
	if err != nil {
		return coned.EntitySelection{}, err
	}
	manager, err := identity.Load(deps.Store, options.Profile, false)
	if err != nil {
		return coned.EntitySelection{}, auth.StorageError(err)
	}
	var result coned.EntitySelection
	meterParent := ""
	for _, entity := range entities {
		h, _ := manager.Handle(identity.Entity{Type: entity.Type, Namespace: "coned-opower", ProviderID: entity.ProviderID})
		if h == account && entity.Type == "account" && entity.Active {
			result.Account = entity.ProviderID
		}
		if h == meter && entity.Type == "meter" && entity.Active {
			result.Meter = entity.ProviderID
			meterParent = entity.ParentProviderID
		}
	}
	if account != "" && result.Account == "" || meter != "" && result.Meter == "" {
		return coned.EntitySelection{}, coned.ErrSelectionRequired
	}
	if result.Account != "" && meterParent != "" && meterParent != result.Account {
		return coned.EntitySelection{}, coned.ErrSelectionRequired
	}
	return result, nil
}

func validEntityHandle(v string) bool {
	for _, p := range []string{"account-", "premise-", "meter-", "register-"} {
		if strings.HasPrefix(v, p) && len(v) > len(p) {
			return true
		}
	}
	return false
}

// handlesInUse reports whether saved aliases or defaults refer to handles
// derived from the profile's current key, which a new key would orphan.
func handlesInUse(deps Dependencies, profile string) bool {
	if deps.ConfigPath == "" {
		return false
	}
	cfg, err := config.Load(deps.ConfigPath)
	if err != nil {
		return false
	}
	selection := cfg.Selections[profile]
	return len(selection.Aliases) != 0 || selection.DefaultAccount != "" || selection.DefaultMeter != ""
}
