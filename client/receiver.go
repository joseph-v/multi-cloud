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
	// "strings"
	"io"
	"context"

	// "github.com/astaxie/beego/httplib"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/opensds/multi-cloud/api/pkg/model"
	"github.com/opensds/multi-cloud/api/pkg/utils"
	"github.com/opensds/multi-cloud/api/pkg/utils/constants"
	// "github.com/opensds/multi-cloud/api/pkg/utils/obs"
	"github.com/opensds/multi-cloud-v4-fannie/s3api/pkg/s3/datatype"
	"github.com/opensds/multi-cloud/client/s3signer"
	"github.com/opensds/multi-cloud/client/s3utils"
	// . "github.com/minio/minio-go"
	"crypto/md5"

)

const (
	HeaderValueJson = "application/json"
	HeaderValueXml = "application/xml"
)
const (
	// signerType      = "SignerType"
	accessKeyID     = "AKIAJSHWLJXYBWTNDL7Q"
	// accessKeyID     = "Auxwfhfop5SdQbUL8lXC"
	secretAccessKey = "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"
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

	//---------------------------------------------------------------------------------------------------------------------------

	// JVP : crete requ
	var createBucketConfigBytes []byte
	var contentBody      io.Reader
	var contentLength    int64
	var contentMD5Base64 string // carries base64 encoded md5sum
	var contentSHA256Hex string // carries hex encoded sha256sum
	
	location := "ap-south-1"

	fmt.Println("JVP:: reqBody=",reqBody)

	if reqBody != nil { 
		// createBucketConfigBytes = []byte("")
		// contentMD5Base64 = s3utils.SumMD5Base64(createBucketConfigBytes)
		// contentSHA256Hex = s3utils.Sum256Hex(createBucketConfigBytes)
		// contentBody = bytes.NewReader(createBucketConfigBytes)
		// contentLength = int64(len(createBucketConfigBytes))

		if location != "us-east-1" && location != "" {
			createBucketConfig := datatype.CreateBucketLocationConfiguration{}
			createBucketConfig.Location = location
			// var createBucketConfigBytes []byte
			createBucketConfigBytes, err = xml.Marshal(createBucketConfig)
			if err != nil {
				return err
			}
			// reqMetadata.contentMD5Base64 = sumMD5Base64(createBucketConfigBytes)
			// reqMetadata.contentSHA256Hex = sum256Hex(createBucketConfigBytes)
			// reqMetadata.contentBody = bytes.NewReader(createBucketConfigBytes)
			// reqMetadata.contentLength = int64(len(createBucketConfigBytes))
			contentMD5Base64 = s3utils.SumMD5Base64(createBucketConfigBytes)
			contentMD5Base64 = base64.StdEncoding.EncodeToString(sumMD5([]byte(createBucketConfigBytes)))
			contentSHA256Hex = s3utils.Sum256Hex(createBucketConfigBytes)
			contentBody = bytes.NewReader(createBucketConfigBytes)
			contentLength = int64(len(createBucketConfigBytes))
			
			
			bodyCloser, ok := contentBody.(io.Closer)
			if ok {
				defer bodyCloser.Close()
			}
		}
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return err
	}
	// contentType, ok := headers[obs.HEADER_CONTENT_TYPE]
	// if !ok {
	// 	log.Printf("Content-Type was not be configured in the request header")
	// }

	/*if reqBody != nil {
		var body []byte

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

		log.Printf("Request body:\n%s\n", string(body))
		if needMarshal {
			// req.Body(body)
		} else {
			// req.Body(reqBody)
		}
	}*/

	//init header
	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	fmt.Println("JVP:: contentMD5Base64=", contentMD5Base64)
	if len(contentMD5Base64) > 0 {
		req.Header.Set("Content-Md5", contentMD5Base64)
	}

	fmt.Println("JVP:: contentLength=", contentLength)
	if contentLength == 0 {
		req.Body = nil
	} else {
		req.Body = ioutil.NopCloser(contentBody)
		// req.Body = (contentBody)
	}
	p, _ := ioutil.ReadAll(req.Body)
	fmt.Println("JVP2:: req Body", string(p))
	fmt.Println("JVP2:: content", string(createBucketConfigBytes))


	req.ContentLength = contentLength

	req.Header.Set("User-Agent", "multi-cloud/v0.10.20")
	// req.Body = nil

	// req.ContentLength = 0
	// req.Header.Set("Content-Md5", metadata.contentMD5Base64)

	emptySHA256Hex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sessionToken   := ""

	shaHeader := emptySHA256Hex
	if contentSHA256Hex != "" {
		shaHeader = contentSHA256Hex
	}
	req.Header.Set("X-Amz-Content-Sha256", shaHeader)
	req = s3signer.SignV4(*req, accessKeyID, secretAccessKey, sessionToken, location)

	fmt.Println("JVP:: Headers", req.Header)
	// JVP : crete requ ends

	ctx := context.Background()
	req = req.WithContext(ctx)

	// transport, err := DefaultTransport(true)
	// if err != nil {
	// 	return nil, err
	// }


	httpClient := &http.Client{
		// Transport:     transport
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// // Handle this specifically for now until future Golang versions fix this issue properly.
		// if urlErr, ok := err.(*url.Error); ok {
		// 	if strings.Contains(urlErr.Err.Error(), "EOF") {
		// 		return nil, &url.Error{
		// 			Op:  urlErr.Op,
		// 			URL: urlErr.URL,
		// 			Err: errors.New("Connection closed by foreign host " + urlErr.URL + ". Retry again."),
		// 		}
		// 	}
		// }
		// return nil, err
		fmt.Println("JVP:: Response is error. ", err)
	}

	// Response cannot be non-nil, report error if thats the case.
	if resp == nil {
		// msg := "Response is empty. " + reportIssue
		// return nil, ErrInvalidArgument(msg)
		fmt.Println("JVP:: Response is empty. ")
	}

	

	// headers[constants.AuthTokenHeader] = k.Auth.TokenID
	// if strings.Contains(url, "/s3") {
	// 	now := time.Now().Format("20060102T150405Z")
	// 	authorizationStr := fmt.Sprintf("OPENSDS-HMAC-SHA256 Credential=%s/%s/%s/s3,SignedHeaders=authorization;host;x-auth-date,Signature=",
	// 		k.Auth.Accesskey, now, k.Auth.Region)
	// 	headers[constants.AuthorizationHeader] = authorizationStr
	// 	headers[constants.SignDateHeader] = now
	// }

	// fmt.Println("JVP:: Before keystone request")

	//return request(url, method, headers, reqBody, respBody, needMarshal, outFileName)









	if err != nil {
		fmt.Println("JVP:: Response error: ", err)
		return err
	}
	//-------------------------------------------------------------------------------------------------------------------------




/*
	req := httplib.NewBeegoRequest(url, strings.ToUpper(method))
	req.SetTimeout(time.Minute*6, time.Minute*6)
	contentType, ok := headers[obs.HEADER_CONTENT_TYPE]
	if !ok {
		log.Printf("Content-Type was not be configured in the request header")
	}

	if reqBody != nil {
		var body []byte

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

		log.Printf("Request body:\n%s\n", string(body))
		if needMarshal {
			req.Body(body)
		} else {
			req.Body(reqBody)
		}
	}

	//init header
	if headers != nil {
		for k, v := range headers {
			req.Header(k, v)
		}
	}

	calculatedSignature := ""
	if "" != calculatedSignature {
		req.Header(constants.AuthorizationHeader, headers[constants.AuthorizationHeader]+calculatedSignature)
	}

	// Get http response.
	resp, err := req.Response()
	if err != nil {
		return err
	}
*/

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
	k.Auth.TenantID = project.ID
	k.Auth.TokenID = token.ID
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

		headers[constants.AuthTokenHeader] = k.Auth.TokenID
		// if strings.Contains(url, "/s3") {
			// now := time.Now().Format("20060102T150405Z")
			// authorizationStr := fmt.Sprintf("OPENSDS-HMAC-SHA256 Credential=%s/%s/%s/s3,SignedHeaders=authorization;host;x-auth-date,Signature=",
			// 	k.Auth.Accesskey, now, k.Auth.Region)
			// headers[constants.AuthorizationHeader] = authorizationStr
			// headers[constants.SignDateHeader] = now
		// }
		return request(url, method, headers, reqBody, respBody, needMarshal, outFileName)
	})
}

func checkHTTPResponseStatusCode(resp *http.Response) error {
	if 400 <= resp.StatusCode && resp.StatusCode <= 599 {
		return fmt.Errorf("response == %d, %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return nil
}
