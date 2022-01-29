package netlify

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/StackExchange/dnscontrol/v3/models"
	"github.com/StackExchange/dnscontrol/v3/pkg/diff"
	"github.com/StackExchange/dnscontrol/v3/pkg/txtutil"
	"github.com/StackExchange/dnscontrol/v3/providers"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/miekg/dns/dnsutil"

	openapiClient "github.com/go-openapi/runtime/client"

	netlifyModels "github.com/netlify/open-api/go/models"
	netlifyOperations "github.com/netlify/open-api/go/plumbing/operations"
	netlify "github.com/netlify/open-api/go/porcelain"
	netlifyContext "github.com/netlify/open-api/go/porcelain/context"
)

type netlifyProvider struct {
	client *netlify.Netlify
}

const (
	apiHostname = "api.netlify.com"
	apiPath     = "/api/v1"
)

var features = providers.DocumentationNotes{
	providers.CanUseAlias:            providers.Cannot(),
	providers.CanUseCAA:              providers.Can(),
	providers.CanUseNAPTR:            providers.Cannot(),
	providers.CanUseDS:               providers.Cannot(),
	providers.CanUsePTR:              providers.Cannot(),
	providers.CanUseSSHFP:            providers.Can(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanAutoDNSSEC:          providers.Cannot(),
	providers.CanUseTLSA:             providers.Cannot(),
	providers.DocCreateDomains:       providers.Cannot(),
	providers.DocDualHost:            providers.Cannot(),
	providers.DocOfficiallySupported: providers.Can(),
	providers.CanGetZones:            providers.Can(),
}

var defaultNameServerNames = []string{
	"dns1.p04.nsone.net",
	"dns2.p04.nsone.net",
	"dns3.p04.nsone.net",
	"dns4.p04.nsone.net",
}

// Register with the dnscontrol system
func init() {
	fns := providers.DspFuncs{
		Initializer: newNetlify,
		//RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType("NETLIFY", fns, features)
}

// Creates the Netlify provider
func newNetlify(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	if m["token"] == "" {
		return nil, fmt.Errorf("no Netlify token provided")
	}

	ctx := context.Background()

	// add OpenAPI Runtime credentials to context
	creds := runtime.ClientAuthInfoWriterFunc(func(r runtime.ClientRequest, _ strfmt.Registry) error {
		r.SetHeaderParam("Authorization", "Bearer "+m["token"])
		return nil
	})
	ctx = netlifyContext.WithAuthInfo(ctx, creds)

	// create an OpenAPI transport
	transport := openapiClient.NewWithClient(apiHostname, apiPath, []string{"https"}, httpClient())
	client := netlify.New(transport, strfmt.Default)
	ctx = context.WithValue(ctx, m["token"], client)

	api := &netlifyProvider{client: client}

	return api, nil
}

func httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   -1,
			DisableKeepAlives:     true,
		},
	}
}

// GetNameservers returns the nameservers for domain.
func (api *netlifyProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	return models.ToNameservers(defaultNameServerNames)
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (api *netlifyProvider) GetZoneRecords(domain string) (models.Records, error) {
	//ctx := context.Background()
	//authInfo := netlifyContext.GetAuthInfo(ctx)

	// Loop over the Netlify records and convert them to native
	records, err := getRecords(api, domain)
	if err != nil {
		return nil, err
	}

	// Where to put the records for returning
	var existingRecords []*models.RecordConfig

	for i := range records {
		r, err := recordToNative(domain, records[i])
		if err != nil {
			return nil, err
		}

		existingRecords = append(existingRecords, r)
	}

	return existingRecords, nil
}

// Gets records for a passed domain by looping through all the zones we have access to from our token
func getRecords(api *netlifyProvider, name string) ([]*netlifyModels.DNSRecord, error) {
	ctx := context.Background()
	authInfo := netlifyContext.GetAuthInfo(ctx)

	// Get the list of domains we have access to
	zoneList, err := api.client.Operations.GetDNSZones(netlifyOperations.NewGetDNSZonesParams().WithContext(ctx), authInfo)
	if err != nil {
		return nil, err
	}

	// Create an ep
	records := []*netlifyModels.DNSRecord{}

	// Loop over the list of zones
	for i := range zoneList.Payload {
		zone := zoneList.Payload[i]

		// Look for a domain which matches what we're looking for
		if zone.Name == name {
			rs, err := api.client.Operations.GetDNSRecords(netlifyOperations.NewGetDNSRecordsParamsWithContext(ctx).WithZoneID(zone.ID), authInfo)
			if err != nil {
				return nil, err
			}

			for j := range rs.Payload {
				r := rs.Payload[j]

				records = append(records, r)
			}
		}
	}

	return records, nil
}

// GetDomainCorrections returns corrections that update a domain.
func (api *netlifyProvider) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	ctx := context.Background()
	authInfo := netlifyContext.GetAuthInfo(ctx)
	dc.Punycode()

	existingRecords, err := api.GetZoneRecords(dc.Name)
	if err != nil {
		return nil, err
	}

	// Normalize
	models.PostProcessRecords(existingRecords)
	txtutil.SplitSingleLongTxt(dc.Records) // Autosplit long TXT records

	differ := diff.New(dc)
	_, create, delete, modify, err := differ.IncrementalDiff(existingRecords)
	if err != nil {
		return nil, err
	}

	var corrections = []*models.Correction{}

	// DeleteDNSRecord: Deletes first so changing type works etc.
	for _, m := range delete {
		id := m.Existing.Original.(*netlifyModels.DNSRecord).ID
		corr := &models.Correction{
			Msg: fmt.Sprintf("%s, Netlify DNSZoneID: %d", m.String(), id),
			F: func() error {
				res, err := api.client.Operations.DeleteDNSRecord(netlifyOperations.NewDeleteDNSRecordParams().WithContext(ctx).WithDNSRecordID(id), authInfo)
				if err != nil {
					return err
				}
				return res
			},
		}
		corrections = append(corrections, corr)
	}

	// CreateDNSRecord
	for _, m := range create {
		req := toReq(dc, m.Desired)
		corr := &models.Correction{
			Msg: m.String(),
			F: func() error {
				res, err := api.client.Operations.CreateDNSRecord(netlifyOperations.NewCreateDNSRecordParams().WithContext(ctx).WithDNSRecord(req), authInfo)
				if err != nil {
					return err
				}
				return res
			},
		}
		corrections = append(corrections, corr)
	}

	// There is no update so DeleteDNSRecord then CreateDNSRecord
	for _, m := range modify {
		id := m.Existing.Original.(*netlifyModels.DNSRecord).ID
		req := toReq(dc, m.Desired)

		corrections = append(corrections,
			&models.Correction{
				Msg: m.String(),
				F: func() error {
					res, err := api.client.Operations.DeleteDNSRecord(netlifyOperations.NewDeleteDNSRecordParams().WithContext(ctx).WithDNSRecordID(id), authInfo)
					if err != nil {
						return err
					}
					return res
				},
			},
			&models.Correction{
				Msg: m.String(),
				F: func() error {
					res, err := api.client.Operations.CreateDNSRecord(netlifyOperations.NewCreateDNSRecordParams().WithContext(ctx).WithDNSRecord(req), authInfo)
					if err != nil {
						return err
					}
					return res
				},
			},
		)
	}

	return corrections, nil
}

// Converts a DNS record to the expected format for dnsconfig
func recordToNative(domain string, r *netlifyModels.DNSRecord) (*models.RecordConfig, error) {
	if !r.Managed {
		return nil, fmt.Errorf(r.Hostname + " is not managed by Netlify")
	}

	// This handles "@" etc.
	name := r.Hostname

	target := r.Value
	// Make target FQDN (#rtype_variations)
	if r.Type == "CNAME" || r.Type == "MX" || r.Type == "NS" || r.Type == "SRV" {
		// If target is the domainname, e.g. cname foo.example.com -> example.com,
		// DO returns "@" on read even if fqdn was written.
		if target == "@" {
			target = domain
		} else if target == "." {
			target = ""
		}
		target = target + "."
	}

	t := &models.RecordConfig{
		Type:         r.Type,
		TTL:          uint32(r.TTL),
		MxPreference: uint16(r.Priority),
		SrvPriority:  uint16(r.Priority),
		Original:     r,
		CaaTag:       r.Tag,
		CaaFlag:      uint8(r.Flag),
	}
	t.SetLabelFromFQDN(name, domain)
	t.SetTarget(target)

	switch rtype := r.Type; rtype {
	case "TXT":
		t.SetTargetTXTString(target)
	default:
		// nothing additional required
	}

	return t, nil
}

func toReq(dc *models.DomainConfig, rc *models.RecordConfig) *netlifyModels.DNSRecordCreate {
	return &netlifyModels.DNSRecordCreate{
		Type:     rc.Type,
		Hostname: dnsutil.AddOrigin(rc.Name, dc.Name),
		Value:    rc.GetTargetField(),
		Priority: int64(rc.SrvPriority),
		Weight:   int64(rc.SrvWeight),
		Port:     int64(rc.SrvPort),
		Flag:     int64(rc.CaaFlag),
		Tag:      rc.CaaTag,
	}
}
