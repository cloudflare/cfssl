// Package core handles the main operations of the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/cryptor"
	"github.com/cloudflare/redoctober/hipchat"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/order"
	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/persist"
	"github.com/cloudflare/redoctober/report"
)

var (
	crypt   *cryptor.Cryptor
	records passvault.Records
	orders  order.Orderer
)

// Each of these structures corresponds to the JSON expected on the
// correspondingly named URI (e.g. the delegate structure maps to the
// JSON that should be sent on the /delegate URI and it is handled by
// the Delegate function below).

type CreateRequest struct {
	Name     string
	Password string
}

type SummaryRequest struct {
	Name     string
	Password string
}

type PurgeRequest struct {
	Name     string
	Password string
}

type DelegateRequest struct {
	Name     string
	Password string

	Uses   int
	Time   string
	Slot   string
	Users  []string
	Labels []string
}

type CreateUserRequest struct {
	Name        string
	Password    string
	UserType    string
	HipchatName string
}

type PasswordRequest struct {
	Name     string
	Password string

	NewPassword string
	HipchatName string
}

type EncryptRequest struct {
	Name     string
	Password string

	Minimum     int
	Owners      []string
	LeftOwners  []string
	RightOwners []string
	Predicate   string

	Data []byte

	Labels []string
}

type ReEncryptRequest EncryptRequest

type DecryptRequest struct {
	Name     string
	Password string

	Data []byte
}

type OwnersRequest struct {
	Data []byte
}

type ModifyRequest struct {
	Name     string
	Password string

	ToModify string
	Command  string
}

type ExportRequest struct {
	Name     string
	Password string
}

type OrderRequest struct {
	Name          string
	Password      string
	Duration      string
	Uses          int
	Users         []string
	EncryptedData []byte
	Labels        []string
}

type OrderInfoRequest struct {
	Name     string
	Password string

	OrderNum string
}

type OrderOutstandingRequest struct {
	Name     string
	Password string
}

type OrderCancelRequest struct {
	Name     string
	Password string

	OrderNum string
}

type StatusRequest struct {
	Name     string
	Password string
}

// These structures map the JSON responses that will be sent from the API

type ResponseData struct {
	Status   string
	Response []byte `json:",omitempty"`
}

type SummaryData struct {
	Status string
	State  string
	Live   map[string]keycache.ActiveUser
	All    map[string]passvault.Summary
}

type DecryptWithDelegates struct {
	Data      []byte
	Secure    bool
	Delegates []string
}

type OwnersData struct {
	Status    string
	Owners    []string
	Labels    []string
	Predicate string
}

type StatusData struct {
	Status string
}

// Helper functions that create JSON responses sent by core

func jsonStatusOk() ([]byte, error) {
	return json.Marshal(ResponseData{Status: "ok"})
}
func jsonStatusError(err error) ([]byte, error) {
	return json.Marshal(ResponseData{Status: err.Error()})
}
func jsonSummary() ([]byte, error) {
	state := crypt.Status()
	return json.Marshal(SummaryData{Status: "ok", State: state.State, Live: crypt.LiveSummary(), All: records.GetSummary()})
}
func jsonResponse(resp []byte) ([]byte, error) {
	return json.Marshal(ResponseData{Status: "ok", Response: resp})
}

// validateUser checks that the username and password passed in are
// correct. If admin is true, the user must be an admin as well.
func validateUser(name, password string, admin bool) error {
	if records.NumRecords() == 0 {
		return errors.New("Vault is not created yet")
	}

	pr, ok := records.GetRecord(name)
	if !ok {
		return errors.New("User not present")
	}

	if err := pr.ValidatePassword(password); err != nil {
		return err
	}

	if admin && !pr.IsAdmin() {
		return errors.New("Admin required")
	}

	return nil
}

//Username must start with an alphanumeric character and can include "-" and "_" after the first
var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9\_\-]*$`).MatchString

// validateName checks that the username and password pass a validation test.
func validateName(name, password string) error {
	if !validName(name) {
		return errors.New("must start with an alphanumeric character and can include \"-\" or \"_\" after the first character")
	}
	if password == "" {
		return errors.New("Password must be at least one character")
	}

	return nil
}

// Init reads the records from disk from a given path
func Init(path string, config *config.Config) error {
	var err error

	tags := map[string]string{"function": "core.Init"}

	defer func() {
		if err != nil {
			report.Check(err, tags)
			log.Printf("core.init failed: %v", err)
		} else {
			log.Printf("core.init success: path=%s", path)
		}
	}()

	if records, err = passvault.InitFrom(path); err != nil {
		err = fmt.Errorf("failed to load password vault %s: %s", path, err)
	}

	crypt, err = cryptor.New(&records, nil, config)
	if err != nil {
		return err
	}

	var hipchatClient hipchat.HipchatClient
	hc := config.HipChat
	if hc.Valid() {
		roomId, err := strconv.Atoi(hc.Room)
		if err != nil {
			return errors.New("core.init unable to use hipchat roomId provided")
		}

		hipchatClient = hipchat.HipchatClient{
			ApiKey: hc.APIKey,
			RoomId: roomId,
			HcHost: hc.Host,
			RoHost: config.UI.Root,
		}

		name := hc.ID
		if name == "" {
			name = "Red October"
		}
		message := name + " has restarted."
		color := hipchat.GreenBackground

		status := crypt.Status()
		if status.State == persist.Inactive {
			message += " @here: persistence is currently " + status.State + "; the restore admins need to restore the saved delegations."
			color = hipchat.RedBackground
		}

		err = hipchatClient.Notify(message, color)
		if err != nil {
			return err
		}
	}

	orders = order.NewOrderer(hipchatClient)
	return nil
}

// Create processes a create request.
func Create(jsonIn []byte) ([]byte, error) {
	var s CreateRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.create failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.create success: user=%s", s.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() != 0 {
		err = errors.New("Vault is already created")
		return jsonStatusError(err)
	}

	// Validate the Name and Password as valid
	if err = validateName(s.Name, s.Password); err != nil {
		return jsonStatusError(err)
	}

	if _, err = records.AddNewRecord(s.Name, s.Password, true, passvault.DefaultRecordType); err != nil {
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Summary processes a summary request.
func Summary(jsonIn []byte) ([]byte, error) {
	var s SummaryRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.summary failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.summary success: user=%s", s.Name)
		}
	}()

	err = crypt.Refresh()
	if err != nil {
		return jsonStatusError(err)
	}

	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		err = errors.New("vault has not been created")
		return jsonStatusError(err)
	}

	if err := validateUser(s.Name, s.Password, false); err != nil {
		return jsonStatusError(err)
	}

	return jsonSummary()
}

// Purge processes a delegation purge request.
func Purge(jsonIn []byte) ([]byte, error) {
	var s PurgeRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.purge failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.purge success: user=%s", s.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		err = errors.New("vault has not been created")
		return jsonStatusError(err)
	}

	// Validate the Name and Password as valid and admin
	if err = validateUser(s.Name, s.Password, true); err != nil {
		return jsonStatusError(err)
	}

	err = crypt.Flush()
	if err != nil {
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Delegate processes a delegation request.
func Delegate(jsonIn []byte) ([]byte, error) {
	var s DelegateRequest
	var err error
	var tags = map[string]string{"function": "core.Delegate"}

	defer func() {
		if err != nil {
			tags["delegation.name"] = s.Name
			tags["delegation.uses"] = fmt.Sprintf("%d", s.Uses)
			tags["delegation.time"] = s.Time
			tags["delegation.users"] = strings.Join(s.Users, ", ")
			tags["delegation.labels"] = strings.Join(s.Labels, ", ")
			log.Printf("core.delegate failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.delegate success: user=%s uses=%d time=%s users=%v labels=%v", s.Name, s.Uses, s.Time, s.Users, s.Labels)
		}
	}()

	if err = json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		err = errors.New("Vault is not created yet")
		return jsonStatusError(err)
	}

	// Validate the Name and Password as valid
	if err = validateName(s.Name, s.Password); err != nil {
		return jsonStatusError(err)
	}

	// Make sure the user we are delegating to exists
	var invalidUsers []string
	for _, user := range s.Users {
		if _, ok := records.GetRecord(user); !ok {
			invalidUsers = append(invalidUsers, user)
		}
	}

	if len(invalidUsers) != 0 {
		err = fmt.Errorf("User(s) not present: %s", strings.Join(invalidUsers, ", "))
		return jsonStatusError(err)
	}

	// Find password record for user and verify that their password
	// matches. If not found then add a new entry for this user.

	pr, found := records.GetRecord(s.Name)
	if found {
		if err = pr.ValidatePassword(s.Password); err != nil {
			return jsonStatusError(err)
		}
	} else {
		if pr, err = records.AddNewRecord(s.Name, s.Password, false, passvault.DefaultRecordType); err != nil {
			return jsonStatusError(err)
		}
	}

	// add signed-in record to active set
	if err = crypt.Delegate(pr, s.Name, s.Password, s.Users, s.Labels, s.Uses, s.Slot, s.Time); err != nil {
		return jsonStatusError(err)
	}

	// Make sure we capture the number who have already delegated.
	for _, delegatedUser := range s.Users {
		if orderKey, found := orders.FindOrder(delegatedUser, s.Labels); found {
			order := orders.Orders[orderKey]

			// Don't re-add names to the list of people who have delegated. Instead
			// just skip them but make sure we count their delegation
			if len(order.OwnersDelegated) == 0 {
				order.OwnersDelegated = append(order.OwnersDelegated, s.Name)
			} else {
				for _, ownerName := range order.OwnersDelegated {
					if ownerName == s.Name {
						continue
					}
					order.OwnersDelegated = append(order.OwnersDelegated, s.Name)
					order.Delegated++
				}
			}
			orders.Orders[orderKey] = order

			// Notify the hipchat room that there was a new delegator
			orders.NotifyDelegation(s.Name, delegatedUser, orderKey, s.Time, s.Labels)

		}
	}

	return jsonStatusOk()
}

// CreateUser processes a create-user request.
func CreateUser(jsonIn []byte) ([]byte, error) {
	var s CreateUserRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.create-user failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.create-user success: user=%s", s.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	// If no UserType if provided use the default one
	if s.UserType == "" {
		s.UserType = passvault.DefaultRecordType
	}

	if records.NumRecords() == 0 {
		err = errors.New("Vault is not created yet")
		return jsonStatusError(err)
	}

	// Validate the Name and Password as valid
	if err = validateName(s.Name, s.Password); err != nil {
		return jsonStatusError(err)
	}

	_, found := records.GetRecord(s.Name)
	if found {
		err = errors.New("User with that name already exists")
		return jsonStatusError(err)
	}

	if _, err := records.AddNewRecord(s.Name, s.Password, false, s.UserType); err != nil {
		return jsonStatusError(err)
	}

	if err = records.ChangePassword(s.Name, s.Password, "", s.HipchatName); err != nil {
		return jsonStatusError(err)
	}
	return jsonStatusOk()
}

// Password processes a password change request.
func Password(jsonIn []byte) ([]byte, error) {
	var err error
	var s PasswordRequest

	defer func() {
		if err != nil {
			log.Printf("core.password failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.password success: user=%s", s.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		err = errors.New("Vault is not created yet")
		return jsonStatusError(err)
	}

	// add signed-in record to active set
	err = records.ChangePassword(s.Name, s.Password, s.NewPassword, s.HipchatName)
	if err != nil {
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Encrypt processes an encrypt request.
func Encrypt(jsonIn []byte) ([]byte, error) {
	var s EncryptRequest
	var err error
	var tags = map[string]string{"function": "core.Encrypt"}

	defer func() {
		if err != nil {
			tags["encrypt.user"] = s.Name
			tags["encrypt.size"] = fmt.Sprintf("%d", len(s.Data))
			report.Check(err, tags)
			log.Printf("core.encrypt failed: user=%s size=%d %v", s.Name, len(s.Data), err)
		} else {
			log.Printf("core.encrypt success: user=%s size=%d", s.Name, len(s.Data))
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	if err = validateUser(s.Name, s.Password, false); err != nil {
		return jsonStatusError(err)
	}

	access := cryptor.AccessStructure{
		Minimum:    s.Minimum,
		Names:      s.Owners,
		LeftNames:  s.LeftOwners,
		RightNames: s.RightOwners,
		Predicate:  s.Predicate,
	}

	resp, err := crypt.Encrypt(s.Data, s.Labels, access)
	if err != nil {
		return jsonStatusError(err)
	}
	return jsonResponse(resp)
}

// ReEncrypt processes an Re-encrypt request.
func ReEncrypt(jsonIn []byte) ([]byte, error) {
	var s ReEncryptRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.re-encrypt failed: user=%s size=%d %v", s.Name, len(s.Data), err)
		} else {
			log.Printf("core.re-encrypt success: user=%s size=%d", s.Name, len(s.Data))
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	if err = validateUser(s.Name, s.Password, false); err != nil {
		return jsonStatusError(err)
	}

	data, _, _, secure, err := crypt.Decrypt(s.Data, s.Name)
	if err != nil {
		return jsonStatusError(err)
	}
	if !secure {
		return jsonStatusError(errors.New("decryption's secure bit is false"))
	}

	access := cryptor.AccessStructure{
		Minimum:    s.Minimum,
		Names:      s.Owners,
		LeftNames:  s.LeftOwners,
		RightNames: s.RightOwners,
		Predicate:  s.Predicate,
	}

	resp, err := crypt.Encrypt(data, s.Labels, access)
	if err != nil {
		return jsonStatusError(err)
	}
	return jsonResponse(resp)
}

// Decrypt processes a decrypt request.
func Decrypt(jsonIn []byte) ([]byte, error) {
	var s DecryptRequest
	var err error
	var tags = map[string]string{"function": "core.Decrypt"}

	defer func() {
		if err != nil {
			tags["decrypt.user"] = s.Name
			report.Check(err, tags)
			log.Printf("core.decrypt failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.decrypt success: user=%s", s.Name)
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	err = validateUser(s.Name, s.Password, false)
	if err != nil {
		return jsonStatusError(err)
	}

	data, allLabels, names, secure, err := crypt.Decrypt(s.Data, s.Name)
	if err != nil {
		return jsonStatusError(err)
	}

	resp := &DecryptWithDelegates{
		Data:      data,
		Secure:    secure,
		Delegates: names,
	}

	tags["delegates"] = strings.Join(names, ", ")

	out, err := json.Marshal(resp)
	if err != nil {
		return jsonStatusError(err)
	}

	// Cleanup any orders that have been fulfilled and notify the room.
	if orderKey, found := orders.FindOrder(s.Name, allLabels); found {
		delete(orders.Orders, orderKey)
		orders.NotifyOrderFulfilled(s.Name, orderKey)
	}
	return jsonResponse(out)
}

// Modify processes a modify request.
func Modify(jsonIn []byte) ([]byte, error) {
	var s ModifyRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.modify failed: user=%s target=%s command=%s %v", s.Name, s.ToModify, s.Command, err)
		} else {
			log.Printf("core.modify success: user=%s target=%s command=%s", s.Name, s.ToModify, s.Command)
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	if err = validateUser(s.Name, s.Password, true); err != nil {
		return jsonStatusError(err)
	}

	if _, ok := records.GetRecord(s.ToModify); !ok {
		err = errors.New("core: record to modify missing")
		return jsonStatusError(err)
	}

	if s.Name == s.ToModify {
		err = errors.New("core: cannot modify own record")
		return jsonStatusError(err)
	}

	switch s.Command {
	case "delete":
		err = records.DeleteRecord(s.ToModify)
	case "revoke":
		err = records.RevokeRecord(s.ToModify)
	case "admin":
		err = records.MakeAdmin(s.ToModify)
	default:
		err = fmt.Errorf("core: unknown command '%s' passed to modify", s.Command)
		return jsonStatusError(err)
	}

	if err != nil {
		return jsonStatusError(err)
	}
	return jsonStatusOk()
}

// Owners processes a owners request.
func Owners(jsonIn []byte) ([]byte, error) {
	var s OwnersRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.owners failed: size=%d %v", len(s.Data), err)
		} else {
			log.Printf("core.owners success: size=%d", len(s.Data))
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	names, labels, predicate, err := crypt.GetOwners(s.Data)
	if err != nil {
		return jsonStatusError(err)
	}

	return json.Marshal(OwnersData{
		Status:    "ok",
		Owners:    names,
		Predicate: predicate,
		Labels:    labels,
	})
}

// Export returns a backed up vault.
func Export(jsonIn []byte) ([]byte, error) {
	var s ExportRequest
	var err error

	defer func() {
		if err != nil {
			log.Printf("core.export failed: user=%s %v", s.Name, err)
		} else {
			log.Printf("core.export success: user=%s", s.Name)
		}
	}()

	err = json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	err = validateUser(s.Name, s.Password, true)
	if err != nil {
		return jsonStatusError(err)
	}

	out, err := json.Marshal(records)
	if err != nil {
		return jsonStatusError(err)
	}

	return jsonResponse(out)
}

// Order will request delegations from other users.
func Order(jsonIn []byte) (out []byte, err error) {
	var o OrderRequest

	defer func() {
		if err != nil {
			log.Printf("core.order failed: user=%s %v", o.Name, err)
		} else {
			log.Printf("core.order success: user=%s", o.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &o); err != nil {
		return jsonStatusError(err)
	}

	if err := validateUser(o.Name, o.Password, false); err != nil {
		return jsonStatusError(err)
	}

	// Get the owners of the ciphertext.
	owners, _, _, err := crypt.GetOwners(o.EncryptedData)
	if err != nil {
		return jsonStatusError(err)
	}
	if o.Duration == "" {
		err = errors.New("Duration required when placing an order.")
		return jsonStatusError(err)
	}
	if o.Uses == 0 {
		err = errors.New("Number of required uses necessary when placing an order.")
		return jsonStatusError(err)
	}

	err = crypt.Refresh()
	if err != nil {
		return jsonStatusError(err)
	}

	orderNum := order.GenerateNum()

	if len(o.Users) == 0 {
		err = errors.New("Must specify at least one user per order.")
		return jsonStatusError(err)
	}
	adminsDelegated, numDelegated := crypt.DelegateStatus(o.Users[0], o.Labels, owners)
	duration, err := time.ParseDuration(o.Duration)
	if err != nil {
		return jsonStatusError(err)
	}
	currentTime := time.Now()
	ord := order.CreateOrder(o.Name,
		orderNum,
		currentTime,
		duration,
		adminsDelegated,
		owners,
		o.Users,
		o.Labels,
		numDelegated)
	orders.Orders[orderNum] = ord
	out, err = json.Marshal(ord)

	// Get a map to any alternative name we want to notify
	altOwners := records.GetAltNamesFromName(orders.AlternateName, owners)

	// Let everyone on hipchat know there is a new order.
	orders.NotifyNewOrder(o.Duration, orderNum, o.Users, o.Labels, o.Uses, altOwners)
	if err != nil {
		return jsonStatusError(err)
	}
	return jsonResponse(out)
}

// OrdersOutstanding will return a list of currently outstanding orders.
func OrdersOutstanding(jsonIn []byte) (out []byte, err error) {
	var o OrderOutstandingRequest

	defer func() {
		if err != nil {
			log.Printf("core.ordersout failed: user=%s %v", o.Name, err)
		} else {
			log.Printf("core.ordersout success: user=%s", o.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &o); err != nil {
		return jsonStatusError(err)
	}

	if err := validateUser(o.Name, o.Password, false); err != nil {
		return jsonStatusError(err)
	}

	out, err = json.Marshal(orders.Orders)
	if err != nil {
		return jsonStatusError(err)
	}
	return jsonResponse(out)
}

// OrderInfo will return a list of currently outstanding order numbers.
func OrderInfo(jsonIn []byte) (out []byte, err error) {
	var o OrderInfoRequest

	defer func() {
		if err != nil {
			log.Printf("core.order failed: user=%s %v", o.Name, err)
		} else {
			log.Printf("core.order success: user=%s", o.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &o); err != nil {
		return jsonStatusError(err)
	}
	if err := validateUser(o.Name, o.Password, false); err != nil {
		return jsonStatusError(err)
	}

	if ord, ok := orders.Orders[o.OrderNum]; ok {
		if out, err = json.Marshal(ord); err != nil {
			return jsonStatusError(err)
		} else if len(out) == 0 {
			return jsonStatusError(errors.New("No order with that number"))
		}

		return jsonResponse(out)
	}

	return jsonStatusError(errors.New("No order with that number"))
}

// OrderCancel will cancel an order given an order num
func OrderCancel(jsonIn []byte) (out []byte, err error) {
	var o OrderCancelRequest

	defer func() {
		if err != nil {
			log.Printf("core.order failed: user=%s %v", o.Name, err)
		} else {
			log.Printf("core.order success: user=%s", o.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &o); err != nil {
		return jsonStatusError(err)
	}

	if err := validateUser(o.Name, o.Password, false); err != nil {
		return jsonStatusError(err)
	}

	if ord, ok := orders.Orders[o.OrderNum]; ok {
		if o.Name == ord.Creator {
			delete(orders.Orders, o.OrderNum)
			out = []byte("Successfully removed order")
			return jsonResponse(out)
		}
	}
	err = errors.New("Invalid Order Number")
	return jsonStatusError(err)
}

// Status returns the current delegation persistence state. In the
// future, this may return more data.
func Status(jsonIn []byte) (out []byte, err error) {
	var req StatusRequest

	defer func() {
		if err != nil {
			log.Printf("core.status failed: user=%s %v", req.Name, err)
		} else {
			log.Printf("core.status success: user=%s", req.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &req); err != nil {
		return jsonStatusError(err)
	}

	if err := validateUser(req.Name, req.Password, false); err != nil {
		return jsonStatusError(err)
	}

	st := crypt.Status()
	resp := &StatusData{Status: st.State}
	if out, err = json.Marshal(resp); err != nil {
		return jsonStatusError(err)
	}

	return jsonResponse(out)
}

// Restore attempts a restoration of the persistence store.
func Restore(jsonIn []byte) (out []byte, err error) {
	var req DelegateRequest
	var tags = map[string]string{"function": "core.Restore"}

	defer func() {
		if err != nil {
			tags["restore.user"] = req.Name
			report.Check(err, tags)
			log.Printf("core.restore failed: user=%s %v", req.Name, err)
		} else {
			log.Printf("core.restore success: user=%s", req.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &req); err != nil {
		return jsonStatusError(err)
	}

	if err := validateUser(req.Name, req.Password, false); err != nil {
		return jsonStatusError(err)
	}

	err = crypt.Restore(req.Name, req.Password, 1, "", req.Time)
	if err != nil && err != cryptor.ErrRestoreDelegations {
		return jsonStatusError(err)
	}

	st := crypt.Status()
	resp := &StatusData{Status: st.State}
	if out, err = json.Marshal(resp); err != nil {
		return jsonStatusError(err)
	}

	return jsonResponse(out)
}

// ResetPersisted clears the persisted user data from the server. This
// request requires an admin.
func ResetPersisted(jsonIn []byte) (out []byte, err error) {
	var req PurgeRequest
	var tags = map[string]string{"function": "core.ResetPersisted"}

	defer func() {
		if err != nil {
			tags["reset-persisted.user"] = req.Name
			report.Check(err, tags)
			log.Printf("core.resetpersisted failed: user=%s %v", req.Name, err)
		} else {
			log.Printf("core.resetpersisted success: user=%s", req.Name)
		}
	}()

	if err = json.Unmarshal(jsonIn, &req); err != nil {
		return jsonStatusError(err)
	}

	if err := validateUser(req.Name, req.Password, true); err != nil {
		return jsonStatusError(err)
	}

	st, err := crypt.ResetPersisted()
	if err != nil {
		return jsonStatusError(err)
	}

	resp := &StatusData{Status: st.State}
	if out, err = json.Marshal(resp); err != nil {
		return jsonStatusError(err)
	}

	return jsonResponse(out)
}
