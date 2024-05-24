package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-filesystems/filesystem-toolchain/wallet"
	xhttp "github.com/minio/minio/cmd/http"
	"github.com/minio/minio/pkg/auth"
)

type WebLoginReq struct {
	Params WebLoginParams `json:"params"`
	Method string         `json:"method"`
}

type WebLoginParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// setCfsAuthHandler to validate authorization header for the incoming request.
func setCfsAuthHandler(h http.Handler) http.Handler {

	// handler for validating incoming authorization headers or body.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := newContext(r, w, "CfsAuth")
		var akStr string
		var skStr string
		var ak *wallet.AccessSecretAK
		var s3Err APIErrorCode
		var err error

		aType := getRequestAuthType(r)
		switch aType {
		case authTypeAnonymous:
			if r.Method == http.MethodPost && r.URL.Path == "/minio/webrpc" {
				payload, err := ioutil.ReadAll(io.LimitReader(r.Body, maxLocationConstraintSize))
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(err.Error()))
					return
				}

				if strings.Index(string(payload), "web.Login") != -1 {
					var webLoginReq WebLoginReq
					err = json.Unmarshal(payload, &webLoginReq)
					if err != nil {
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte(err.Error()))
						return
					}

					reqAkStr := webLoginReq.Params.Username
					reqSkStr := webLoginReq.Params.Password
					_, found := globalCfsCred.Get(reqAkStr)
					if !found {
						akObj, calcSkStr, err := CheckAccessSecret(ctx, reqAkStr)
						if err != nil || calcSkStr != reqSkStr {
							w.WriteHeader(http.StatusUnauthorized)
							w.Write([]byte("web.Login access secret invalid"))
							return
						}
						akStr = reqAkStr
						skStr = calcSkStr
						ak = akObj
					}
				}

				r.Body = ioutil.NopCloser(bytes.NewReader(payload))
			}

		case authTypePresignedV2, authTypeSignedV2:
			akStr, _, s3Err = getReqAccessKeyV2Str(r)
			if s3Err != ErrNone {
				writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
				return
			}
			_, found := globalCfsCred.Get(akStr)
			if !found {
				ak, skStr, err = CheckAccessSecret(ctx, akStr)
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(err.Error()))
					return
				}
			}

		case authTypeSigned, authTypePresigned:
			region := globalServerRegion
			akStr, _, s3Err = getReqAccessKeyV4Str(r, region, serviceS3)
			if s3Err != ErrNone {
				writeErrorResponse(ctx, w, errorCodes.ToAPIErr(s3Err), r.URL, guessIsBrowserReq(r))
				return
			}
			_, found := globalCfsCred.Get(akStr)
			if !found {
				ak, skStr, err = CheckAccessSecret(ctx, akStr)
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(err.Error()))
					return
				}
			}
		}

		if akStr != "" && skStr != "" && ak != nil {
			_, found := globalCfsCred.Get(akStr)
			if !found {
				reqCred, err := auth.CreateCredentials(akStr, skStr)
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(err.Error()))
					return
				}
				reqCred.Expiration = time.Unix(int64(ak.Exp), 0)
				timeDiff := reqCred.Expiration.Sub(time.Now())
				globalCfsCred.Set(akStr, reqCred, timeDiff)
			}
		}

		h.ServeHTTP(w, r)
	})
}

func getReqAccessKeyV2Str(r *http.Request) (string, bool, APIErrorCode) {
	if accessKey := r.URL.Query().Get(xhttp.AmzAccessKeyID); accessKey != "" {
		return accessKey, true, ErrNone
	}

	// below is V2 Signed Auth header format, splitting on `space` (after the `AWS` string).
	// Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature
	authFields := strings.Split(r.Header.Get(xhttp.Authorization), " ")
	if len(authFields) != 2 {
		return "", false, ErrMissingFields
	}

	// Then will be splitting on ":", this will seprate `AWSAccessKeyId` and `Signature` string.
	keySignFields := strings.Split(strings.TrimSpace(authFields[1]), ":")
	if len(keySignFields) != 2 {
		return "", false, ErrMissingFields
	}

	return keySignFields[0], true, ErrNone
}

func getReqAccessKeyV4Str(r *http.Request, region string, stype serviceType) (string, bool, APIErrorCode) {
	ch, s3Err := parseCredentialHeader("Credential="+r.URL.Query().Get(xhttp.AmzCredential), region, stype)
	if s3Err != ErrNone {
		// Strip off the Algorithm prefix.
		v4Auth := strings.TrimPrefix(r.Header.Get("Authorization"), signV4Algorithm)
		authFields := strings.Split(strings.TrimSpace(v4Auth), ",")
		if len(authFields) != 3 {
			return "", false, ErrMissingFields
		}
		ch, s3Err = parseCredentialHeader(authFields[0], region, stype)
		if s3Err != ErrNone {
			return "", false, s3Err
		}
	}
	return ch.accessKey, true, ErrNone
}
