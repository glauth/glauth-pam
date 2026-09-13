package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/ldap"
	"github.com/msteinert/pam"
	"github.com/rs/zerolog"
)

func copyBytes(x []byte) []byte {
	y := make([]byte, len(x))
	copy(y, x)
	return y
}

func convertID(strID string) int {
	id, err := strconv.Atoi(strID)
	if err != nil {
		return -1
	}
	return id
}

func (h pamHandler) localUserIds() ([]string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}

	defer file.Close()

	lines := bufio.NewReader(file)
	var entries []string
	for {
		line, _, err := lines.ReadLine()
		if err != nil {
			break
		}
		fs := strings.Split(string(copyBytes(line)), ":")
		// https://en.wikipedia.org/wiki/Passwd#Password_file
		// expect username:*:uid:gid
		if len(fs) < 3 {
			h.log.Error().Msg(fmt.Sprintf("Unexpected number of fields in /etc/passwd at '%s'", line))
			continue
		}
		entries = append(entries, fs[2])
	}
	return entries, nil
}

// GroupEntry collects all members of a group
type GroupEntry struct {
	Gid         string
	MemberNames []string
}

func (h pamHandler) collectAllLocalGroups() ([]GroupEntry, error) {
	file, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}

	defer file.Close()

	lines := bufio.NewReader(file)
	var entries []GroupEntry
	for {
		line, _, err := lines.ReadLine()
		if err != nil {
			break
		}
		fs := strings.Split(string(copyBytes(line)), ":")
		// https://en.wikipedia.org/wiki/Group_identifier
		// expect group:*:gid
		if len(fs) < 3 {
			h.log.Error().Msg(fmt.Sprintf("Unexpected number of fields in /etc/group at '%s'", line))
			continue
		}
		// prefer FieldsFunc over Split so that we drop empty entries
		splitMembersFunc := func(c rune) bool {
			return c == ','
		}
		members := strings.FieldsFunc(fs[len(fs)-1], splitMembersFunc)
		entries = append(entries, GroupEntry{fs[2], members})
	}
	return entries, nil
}

func authenticateUserPAM(user *config.User, bindSimplePw string) error {
	// Note: While there is golang bindings to interface with unix_pam (e.g. github.com/msteinert/pam),
	//		 these have the limitation that only the user running the glauth process is able to authenticate
	//		 unless explicitly spawned as root which is not advisable.
	//	     see discussions on https://mariadb.com/kb/en/authentication-plugin-pam/+comments/334
	//		 see comment in https://github.com/msteinert/pam/blob/master/example_test.go line 22
	//
	// One possible workaround which is fine for the time being is adding the user executing glauth to the 'shadow' group

	// try to login
	t, err := pam.StartFunc("", user.Name, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return bindSimplePw, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", errors.New("Unrecognized PAM message style")
	})

	if err == nil {
		err = t.Authenticate(0)
	}
	return err
}

type pamHandler struct {
	backend      config.Backend
	log          *zerolog.Logger
	ldohelper    handler.LDAPOpsHelper
	cfg          *config.Config
	capSearchGid string
}

func (h pamHandler) GetBackend() config.Backend {
	return h.backend
}
func (h pamHandler) GetLog() *zerolog.Logger {
	return h.log
}
func (h pamHandler) GetCfg() *config.Config {
	return h.cfg
}
func (h pamHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return nil
}

func (h pamHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	return h.ldohelper.Bind(context.Background(), h, bindDN, bindSimplePw, conn)
}

func (h pamHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	return h.ldohelper.Search(context.Background(), h, bindDN, searchReq, conn)
}

// Add is not yet supported for the pam backend
func (h pamHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the pam backend
func (h pamHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the pam backend
func (h pamHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// FindUser with the given username. Called by the ldap backend to authenticate the bind. Optional
func (h pamHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (found bool, ldapUser config.User, err error) {
	h.log.Info().Str("userName", userName).Bool("searchByUPN", searchByUPN).Msg("FindUser")
	if searchByUPN {
		h.log.Info().Msg("Searching by UPN is not supported")
		return false, config.User{}, nil
	}

	localUser, err := user.Lookup(userName)
	if err != nil {
		// user is unknown
		h.log.Error().Str("username", userName).Err(err).Msg("FindUser failed - no such user")
		return false, config.User{}, err
	}

	searchCapability := config.Capability{Action: "search", Object: "*"}
	ldapUser = config.User{}
	ldapUser.Name = localUser.Username
	ldapUser.PassAppCustom = authenticateUserPAM
	if len(localUser.Name) > 0 {
		ldapUser.GivenName = localUser.Name
	} else {
		ldapUser.GivenName = localUser.Username
	}
	ldapUser.PrimaryGroup = convertID(localUser.Gid)
	if localUser.Gid == h.capSearchGid {
		ldapUser.Capabilities = []config.Capability{searchCapability}
	}
	ldapUser.Disabled = false
	ldapUser.UnixID = convertID(localUser.Uid)
	ldapUser.UIDNumber = convertID(localUser.Uid)
	ldapUser.Homedir = localUser.HomeDir

	localGroups, err := localUser.GroupIds()
	if err == nil {
		ldapUser.OtherGroups = make([]int, len(localGroups))
		for index, gid := range localGroups {
			ldapUser.OtherGroups[index] = convertID(gid)
			if gid == h.capSearchGid {
				ldapUser.Capabilities = []config.Capability{searchCapability}
			}
		}
	} else {
		// user has no groups
		h.log.Error().Str("username", userName).Err(err).Msg("FindUser - user without groups")
	}

	return true, ldapUser, nil
}

func (h pamHandler) FindGroup(ctx context.Context, groupName string) (found bool, group config.Group, err error) {
	allLocalGroups, err := h.collectAllLocalGroups()
	if err != nil {
		h.log.Error().Err(err).Msg("FindGroup - failed to enumerate groups")
	}
	for _, g := range allLocalGroups {
		localGroup, err := user.LookupGroupId(g.Gid)
		if err != nil {
			h.log.Error().Str("gid", g.Gid).Err(err).Msg("FindGroup - bad group")
			continue
		}

		if localGroup.Name != groupName {
			continue
		}

		ldapGroup := config.Group{}
		ldapGroup.Name = localGroup.Name
		ldapGroup.UnixID = convertID(localGroup.Gid)
		ldapGroup.GIDNumber = convertID(localGroup.Gid)
		return true, ldapGroup, nil
	}
	return false, config.Group{}, nil
}

func (h pamHandler) getGroupMemberDN(group GroupEntry) (memberNames []string, memberUids []string) {
	for _, name := range group.MemberNames {
		localUser, err := user.Lookup(name)
		if err != nil {
			h.log.Error().Str("name", name).Str("group", group.Gid).Err(err).Msg("Bad user")
			continue
		}
		primaryGroup, err := user.LookupGroupId(localUser.Gid)
		if err != nil {
			h.log.Error().Str("name", name).Str("gid", localUser.Gid).Err(err).Msg("User without primary group")
			continue
		}
		dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.backend.NameFormatAsArray[0], localUser.Username, h.backend.GroupFormatAsArray[0], primaryGroup.Name, h.backend.BaseDN)
		memberNames = append(memberNames, dn)
		memberUids = append(memberUids, localUser.Username)
	}
	return memberNames, memberUids
}

func (h pamHandler) FindPosixGroups(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	groups, err := h.collectAllLocalGroups()
	if err != nil {
		return nil, err
	}
	entries := []*ldap.Entry{}
	for _, g := range groups {
		localGroup, err := user.LookupGroupId(g.Gid)
		if err != nil {
			h.log.Error().Str("gid", g.Gid).Err(err).Msg("Bad group")
			continue
		}
		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{localGroup.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{localGroup.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{localGroup.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{localGroup.Gid}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup"}})

		memberNames, memberUids := h.getGroupMemberDN(g)
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: memberNames})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: memberUids})

		dn := fmt.Sprintf("%s=%s,ou=groups,%s", h.backend.GroupFormatAsArray[0], localGroup.Name, h.backend.BaseDN)
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}
	return entries, nil
}

func (h pamHandler) getUserGroupDN(localUser *user.User) (localGroupDN []string) {
	localGroups, err := localUser.GroupIds()
	if err == nil {
		for _, gid := range localGroups {
			userGroup, err := user.LookupGroupId(gid)
			if err != nil {
				h.log.Error().Str("gid", gid).Err(err).Msg("Bad group")
				continue
			}
			dn := fmt.Sprintf("%s=%s,ou=groups,%s", h.backend.GroupFormatAsArray[0], userGroup.Name, h.backend.BaseDN)
			localGroupDN = append(localGroupDN, dn)
		}
	}
	return localGroupDN
}

func (h pamHandler) FindPosixAccounts(ctx context.Context, hierarchy string) (entrylist []*ldap.Entry, err error) {
	users, err := h.localUserIds()
	if err != nil {
		return nil, err
	}
	entries := []*ldap.Entry{}
	for _, u := range users {
		localUser, err := user.LookupId(u)
		if err != nil {
			h.log.Error().Str("uid", u).Err(err).Msg("Bad user")
			continue
		}
		localGroup, err := user.LookupGroupId(localUser.Gid)
		if err != nil {
			h.log.Error().Str("user", localUser.Username).Str("gid", localUser.Gid).Err(err).Msg("Bad primary group")
			continue
		}

		attrs := []*ldap.EntryAttribute{}
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{localUser.Username}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{localUser.Username}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{localGroup.Name}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "uidNumber", Values: []string{localUser.Uid}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "accountStatus", Values: []string{"active"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount"}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s", localUser.Username)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gecos", Values: []string{fmt.Sprintf("%s", localUser.Username)}})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{localUser.Gid}})

		if len(localUser.Name) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{localUser.Name}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "displayName", Values: []string{localUser.Name}})
		} else {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{localUser.Username}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "displayName", Values: []string{localUser.Username}})
		}

		if len(localUser.HomeDir) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "homeDirectory", Values: []string{localUser.HomeDir}})
		}

		localGroupDN := h.getUserGroupDN(localUser)
		if len(localGroupDN) > 0 {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: localGroupDN})
		}

		var dn string
		if hierarchy == "" {
			dn = fmt.Sprintf("%s=%s,%s=%s,%s", h.backend.NameFormatAsArray[0], localUser.Username, h.backend.GroupFormatAsArray[0], localGroup.Name, h.backend.BaseDN)
		} else {
			dn = fmt.Sprintf("%s=%s,%s=%s,%s,%s", h.backend.NameFormatAsArray[0], localUser.Username, h.backend.GroupFormatAsArray[0], localGroup.Name, hierarchy, h.backend.BaseDN)
		}
		entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	}
	return entries, nil
}

func (h pamHandler) Close(boundDN string, conn net.Conn) error {
	return nil
}

// NewPamHandler creates a new instance of the pam backend
func NewPamHandler(opts ...handler.Option) handler.Handler {
	options := handler.NewOptions(opts...)

	// determine which gid gets search capability
	localGroup, err := user.LookupGroup(options.Backend.GroupWithSearchCapability)
	if err != nil {
		options.Logger.Error().Err(err).Msg("Failed to resolve handler.groupWithSearchCapability: No such group '" + options.Backend.GroupWithSearchCapability + "'")
	} else {
		options.Logger.Info().Msg("Members of group '" + options.Backend.GroupWithSearchCapability + "' will get search capability")
	}

	return pamHandler{
		backend:      options.Backend,
		log:          options.Logger,
		ldohelper:    options.LDAPHelper,
		cfg:          options.Config,
		capSearchGid: localGroup.Gid,
	}
}
