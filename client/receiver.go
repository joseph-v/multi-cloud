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
	"encoding/json"
	"encoding/xml"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"bytes"
	"io"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/opensds/multi-cloud/api/pkg/model"
	"github.com/opensds/multi-cloud/api/pkg/utils"
	"github.com/opensds/multi-cloud/client/s3signer"
	"github.com/opensds/multi-cloud/client/s3utils"
	"github.com/opensds/multi-cloud/api/pkg/utils/obs"
	"crypto/md5"

)

// Update these before using CLI
const (
	accessKeyID     = "AKIAJSHWLJXYBWTNDL7Q"
	secretAccessKey = "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"
)

const (
	emptySHA256Hex  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	HeaderValueJson = "application/json"
	HeaderValueXml = "application/xml"
	AuthTokenHeader = "X-Auth-Token"
)

// NewHTTPError implementation
func NewHTTPError(code int, msg string) error {
	return &HTTPError{Code: code, Msg: msg}
}

// HTTPError implementation
type HTTPError struct {
	Code int
	Desc string
	Msg  string
}

// Decode implementation
func (e *HTTPError) Decode() {
	errSpec := model.ErrorSpec{}
	err := json.Unmarshal([]byte(e.Msg), &errSpec)
	if err == nil {
		e.Msg = errSpec.Message
	}

}

// Error implementation
func (e *HTTPError) Error() string {
	e.Decode()
	return fmt.Sprintf("Code: %v, Desc: %s, Msg: %v", e.Code, http.StatusText(e.Code), e.Msg)
}

// HeaderOption implementation
type HeaderOption map[string]string

// Receiver implementation
type Receiver interface {
	Recv(url string, method string, headers HeaderOption,
		reqBody interface{}, respBody interface{}, needMarshal bool, outFileName string) error
}

// NewReceiver implementation
func NewReceiver() Receiver {
	return &receiver{}
}

// sumMD5 calculate md5 sum for an input byte array
func sumMD5(data []byte) []byte {
	hash := md5.New()
	hash.Write(data)
	return hash.Sum(nil)
}
// request implementation
func request(url string, method string, headers HeaderOption,
	reqBody interface{}, respBody interface{}, needMarshal bool, outFileName string) error {
	log.Printf("\nurl=%+v\nmethod=%+v\nheaders=%+v\nreqBody=%+v\nrespBody=%+v\nneedMarshal=%+v\noutFileName=%+v\n",
		url, method, headers, reqBody, respBody, needMarshal, outFileName)
	var err error

	var contentBody      io.Reader
	var contentLength    int64
	var contentMD5Base64 string // carries base64 encoded md5sum
	var contentSHA256Hex string // carries hex encoded sha256sum
	
	location := "ap-south-1"

	contentType, ok := headers[obs.HEADER_CONTENT_TYPE]
	if !ok {
		log.Printf("Content-Type was not be configured in the request header")
	}

	var body []byte

	if reqBody != nil {
		if needMarshal {
			switch contentType {
			case HeaderValueJson:
				body, err = json.MarshalIndent(reqBody, "", "  ")
				if err != nil {
					return err
				}
				break
			case HeaderValueXml:
				body, err = xml.Marshal(reqBody)
				if err != nil {
					return err
				}

				break
			default:
				log.Printf("Content-Type is not application/json nor application/xml\n")
			}
		}

		if location != "us-east-1" && location != "" {
			contentMD5Base64 = s3utils.SumMD5Base64(body)
			contentMD5Base64 = base64.StdEncoding.EncodeToString(sumMD5([]byte(body)))
			contentSHA256Hex = s3utils.Sum256Hex(body)
			contentBody = bytes.NewReader(body)
			contentLength = int64(len(body))

			bodyCloser, ok := contentBody.(io.Closer)
			if ok {
				defer bodyCloser.Close()
			}
		}
	}

	var buf io.Reader
	if reqBody != nil {
		buf = bytes.NewBuffer(body)
	}

	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return err
	}

	//init header
	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	if len(contentMD5Base64) > 0 {
		req.Header.Set("Content-Md5", contentMD5Base64)
	}

	req.ContentLength = contentLength
	sessionToken   := "dummy-session-token"
	shaHeader := emptySHA256Hex
	if contentSHA256Hex != "" {
		shaHeader = contentSHA256Hex
	}
	req.Header.Set("X-Amz-Content-Sha256", shaHeader)
	req = s3signer.SignV4(*req, accessKeyID, secretAccessKey, sessionToken, location)

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("HTTP request failed, error: %+v", err)
		return err
	}

	// Response cannot be non-nil, report error if thats the case.
	if resp == nil {
		log.Printf("HTTP request Response is empty. ")
	}

	if 400 <= resp.StatusCode && resp.StatusCode <= 599 {
		log.Printf("Response statusCode: %+v\n", resp.StatusCode)
		return NewHTTPError(resp.StatusCode, "")
	}

	rbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ioutil.ReadAll failed, err: %+v\n", err)
		return err
	}

	defer resp.Body.Close()
	log.Printf("Response Status: %s\nResponse Body:\n%s\n", resp.Status, string(rbody))
	if (nil == rbody) || ("" == string(rbody)) {
		return nil
	}

	if "" == outFileName {
		if nil == respBody {
			log.Printf("Http request response Body is nil ")
			return nil
		}

		var respContentType string
		respContentTypes, ok := resp.Header["Content-Type"]
		log.Printf("ok=%+v, respContentTypes=%+v, len=%v\n", ok, respContentTypes, len(respContentTypes))

		if ok && len(respContentTypes) > 0 {
			respContentType = respContentTypes[0]
		}

		switch respContentType {
		case HeaderValueJson:
			if err = json.Unmarshal(rbody, respBody); err != nil {
				return fmt.Errorf("failed to unmarshal result message: %v", err)
			}
			log.Printf("application/json, respBody=%+v\n", respBody)
			break
		case HeaderValueXml, "text/xml; charset=utf-8":
			if err = xml.Unmarshal(rbody, respBody); err != nil {
				return fmt.Errorf("failed to unmarshal result message: %v", err)
			}
			log.Printf("application/xml, respBody=%+v\n", respBody)
			break
		default:
			log.Printf("Failure to process the response body!")
		}
	} else {
		path := fmt.Sprintf("./%s", outFileName)
		file, err := os.Create(path)
		if err != nil {
			log.Printf("Failed to create file:%+v\n", err)
		}
		defer file.Close()

		n, err := file.Write(rbody)
		if err != nil {
			log.Printf("Failed to Write file,err:%+v\n, n:%+v\n", err, n)
		}
		log.Printf("Save file successfully, n:%+v\n", n)
	}

	return nil
}

type receiver struct{}

func (*receiver) Recv(url string, method string, headers HeaderOption,
	reqBody interface{}, respBody interface{}, needMarshal bool, outFileName string) error {
	return request(url, method, headers, reqBody, respBody, needMarshal, outFileName)
}

// NewKeystoneReciver implementation
func NewKeystoneReciver(auth *KeystoneAuthOptions) Receiver {
	k := &KeystoneReciver{Auth: auth}
	err := k.GetToken()
	if err != nil {
		log.Printf("Failed to get token: %v", err)
	}
	return k
}

// KeystoneReciver implementation
type KeystoneReciver struct {
	Auth *KeystoneAuthOptions
}

// GetToken implementation
func (k *KeystoneReciver) GetToken() error {
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: k.Auth.IdentityEndpoint,
		Username:         k.Auth.Username,
		UserID:           k.Auth.UserID,
		Password:         k.Auth.Password,
		DomainID:         k.Auth.DomainID,
		DomainName:       k.Auth.DomainName,
		TenantID:         k.Auth.TenantID,
		TenantName:       k.Auth.TenantName,
		AllowReauth:      k.Auth.AllowReauth,
	}

	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return fmt.Errorf("When get auth client: %v", err)
	}

	// Only support keystone v3
	identity, err := openstack.NewIdentityV3(provider, gophercloud.EndpointOpts{})
	if err != nil {
		return fmt.Errorf("When get identity session: %v", err)
	}
	r := tokens.Create(identity, &opts)
	token, err := r.ExtractToken()
	if err != nil {
		return fmt.Errorf("When get extract token session: %v", err)
	}
	project, err := r.ExtractProject()
	if err != nil {
		return fmt.Errorf("When get extract project session: %v", err)
	}
	user, err := r.ExtractUser()
	if err != nil {
		return fmt.Errorf("When get extract user session: %v", err)
	}
	k.Auth.TenantID = project.ID
	k.Auth.TokenID = token.ID
	k.Auth.UserID = user.ID
	return nil
}

// Recv implementation
func (k *KeystoneReciver) Recv(url string, method string, headers HeaderOption,
	reqBody interface{}, respBody interface{}, needMarshal bool, outFileName string) error {
	desc := fmt.Sprintf("%s %s", method, url)
	return utils.Retry(2, desc, true, func(retryIdx int, lastErr error) error {
		if retryIdx > 0 {
			err, ok := lastErr.(*HTTPError)
			if ok && err.Code == http.StatusUnauthorized {
				err := k.GetToken()
				if err != nil {
					log.Printf("Failed to get token: %v", err)
				}
			} else {
				return lastErr
			}
		}

		headers[AuthTokenHeader] = k.Auth.TokenID
		return request(url, method, headers, reqBody, respBody, needMarshal, outFileName)
	})
}

func checkHTTPResponseStatusCode(resp *http.Response) error {
	if 400 <= resp.StatusCode && resp.StatusCode <= 599 {
		return fmt.Errorf("response == %d, %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return nil
}
