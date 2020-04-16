// Copyright 2019 The OpenSDS Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"strings"
	"os"
)

// NewAccessKeyMgr implementation
func NewAccessKeyMgr(r Receiver, edp string, tenantID string, userID string) *AccessKeyMgr {
	return &AccessKeyMgr{
		Receiver: r,
		Endpoint: edp,
		TenantID: tenantID,
		UserID : userID,
	}
}

// AccessKeyMgr implementation
type AccessKeyMgr struct {
	Receiver
	Endpoint string
	TenantID string
	UserID   string
}

type AccessKeyDetail struct {

}

// CreateAccessKey implementation
func (a *AccessKeyMgr) CreateAccessKey(args []string) (*Credentials, error) {
	var res Credentials
	url := strings.Join([]string{
		os.Getenv("OS_AUTH_URL"),
		"v3", "credentials"}, "/")


	blob :=  "{\"access\":\""+ args[0] + "\",\"secret\":\"" + args[1] + "\"}"

	cred := Credentials{
		Blob: blob,
		Type: "ec2",
		ProjectId: a.TenantID,
		UserId: a.UserID,
	}

	body := ListAccessKeyRequest { cred }
	return &res, a.Recv(url, "POST", JSONHeaders, body, &res, true, "")
}

// // DeleteAccessKey implementation
// func (a *AccessKeyMgr) DeleteAccessKey(ID string) error {
// 	// url := strings.Join([]string{
// 	// 	b.Endpoint,
// 	// 	GenerateAccessKeyURL(b.TenantID, ID)}, "/")

// 	// return b.Recv(url, "DELETE", JSONHeaders, nil, nil, true, "")
// }

// // GetAccessKey implementation
// func (b *AccessKeyMgr) GetAccessKey(ID string) (*backend.AccessKeyDetail, error) {
// 	var res backend.AccessKeyDetail
// 	// url := strings.Join([]string{
// 	// 	b.Endpoint,
// 	// 	GenerateAccessKeyURL(b.TenantID, ID)}, "/")

// 	// if err := b.Recv(url, "GET", JSONHeaders, nil, &res, true, ""); err != nil {
// 	// 	return nil, err
// 	// }

// 	return &res, nil
// }

type Links struct {
	Self         string 	   `json:"self,omitempty"`
	previous     *Links        `json:"previous,omitempty"`
	next         *Links        `json:"next,omitempty"`
}
type Credentials struct {
	UserId 		string `json:"user_id,omitempty"`
	Blob 		string `json:"blob,omitempty"`
	ProjectId 	string `json:"project_id,omitempty"`
	Type 		string `json:"type,omitempty"`
	Id 			string `json:"id,omitempty"`
	Link     	Links  `json:"links,omitempty"`
}

type ListAccessKeyRequest struct {
	Credential Credentials 	  `json:"credential,omitempty"`
}
type ListAccessKeyResponse struct {
	Credential []*Credentials `json:"credentials,omitempty"`
	Link     Links            `json:"links,omitempty"`
}

// ListAccessKeys implementation
func (a *AccessKeyMgr) ListAccessKeys() (*ListAccessKeyResponse, error) {
	var res ListAccessKeyResponse

	url := strings.Join([]string{
		os.Getenv("OS_AUTH_URL"),
		"v3", "credentials"}, "/")

	if err := a.Recv(url, "GET", JSONHeaders, nil, &res, true, ""); err != nil {
		return nil, err
	}
	// os.Getenv("OS_AUTH_URL")
	return &res, nil
}

// // UpdateAccessKey implementation
// func (b *AccessKeyMgr) UpdateAccessKey(body *backend.UpdateAccessKeyRequest) (*backend.AccessKeyDetail, error) {
// 	var res backend.AccessKeyDetail
// 	// url := strings.Join([]string{
// 	// 	b.Endpoint,
// 	// 	GenerateAccessKeyURL(b.TenantID, body.Id)}, "/")

// 	// if err := b.Recv(url, "PUT", JSONHeaders, body, &res, true, ""); err != nil {
// 	// 	return nil, err
// 	// }

// 	return &res, nil
// }
