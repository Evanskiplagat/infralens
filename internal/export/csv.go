package export

import (
	"encoding/csv"
	"io"

	"infralens/internal/findings"
	"infralens/internal/resource"
)

// WriteResourcesCSV writes one row per resource, suitable for spreadsheet
// review or feeding into other tooling.
func WriteResourcesCSV(w io.Writer, resources []resource.Resource) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{"id", "kind", "name", "region", "account_id", "provider_id"}); err != nil {
		return err
	}
	for _, r := range resources {
		if err := cw.Write([]string{r.ID, string(r.Kind), r.Name, r.Region, r.AccountID, r.ProviderID}); err != nil {
			return err
		}
	}
	return cw.Error()
}

// WriteFindingsCSV writes one row per finding.
func WriteFindingsCSV(w io.Writer, fs []findings.Finding) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{"rule_id", "resource_id", "severity", "title", "description"}); err != nil {
		return err
	}
	for _, f := range fs {
		if err := cw.Write([]string{f.RuleID, f.ResourceID, string(f.Severity), f.Title, f.Description}); err != nil {
			return err
		}
	}
	return cw.Error()
}
