package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/malikssm/malik/internal/vault"
)

// handleAWSRequest implements the AWS Secrets Manager JSON 1.1 wire protocol
// so standard AWS SDKs (boto3, aws-sdk-js, aws-sdk-go, aws CLI) can query MalikSSM directly.
func (s *Server) handleAWSRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	caller := getCaller(r)
	target := r.Header.Get("X-Amz-Target")
	op := strings.TrimPrefix(target, "secretsmanager.")

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAWSError(w, http.StatusBadRequest, "SerializationException", "Invalid JSON payload")
		return
	}

	switch op {
	case "GetSecretValue":
		secretID, _ := body["SecretId"].(string)
		stage, _ := body["VersionStage"].(string)
		verID, _ := body["VersionId"].(string)
		verNum, _ := strconv.Atoi(strings.TrimPrefix(verID, "v"))

		sec, err := s.store.GetSecret(caller, secretID, verNum, stage)
		if err != nil {
			if err == vault.ErrSecretNotFound {
				writeAWSError(w, http.StatusBadRequest, "ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
				return
			}
			writeAWSError(w, http.StatusBadRequest, "AccessDeniedException", err.Error())
			return
		}

		resp := map[string]any{
			"ARN":           sec.ARN,
			"Name":          sec.Path,
			"VersionId":     fmt.Sprintf("v%d", sec.Version),
			"SecretString":  sec.Value,
			"VersionStages": sec.Stages,
			"CreatedDate":   float64(sec.UpdatedAt.Unix()),
		}
		_ = json.NewEncoder(w).Encode(resp)

	case "ListSecrets":
		items, err := s.store.ListSecrets(caller, "")
		if err != nil {
			writeAWSError(w, http.StatusInternalServerError, "InternalServiceError", err.Error())
			return
		}
		secretList := make([]map[string]any, 0, len(items))
		for _, item := range items {
			awsTags := make([]map[string]string, 0, len(item.Tags))
			for _, t := range item.Tags {
				awsTags = append(awsTags, map[string]string{"Key": "tag", "Value": t})
			}
			secretList = append(secretList, map[string]any{
				"ARN":             item.ARN,
				"Name":            item.Path,
				"Description":     item.Description,
				"LastChangedDate": float64(item.UpdatedAt.Unix()),
				"CreatedDate":     float64(item.CreatedAt.Unix()),
				"Tags":            awsTags,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"SecretList": secretList,
		})

	case "CreateSecret", "PutSecretValue", "UpdateSecret":
		secretID, _ := body["SecretId"].(string)
		if secretID == "" {
			secretID, _ = body["Name"].(string)
		}
		secString, _ := body["SecretString"].(string)
		desc, _ := body["Description"].(string)

		meta, err := s.store.PutSecret(caller, vault.PutSecretInput{
			Path:        secretID,
			Description: desc,
			Value:       secString,
		})
		if err != nil {
			writeAWSError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ARN":           meta.ARN,
			"Name":          meta.Path,
			"VersionId":     fmt.Sprintf("v%d", meta.CurrentVersion),
			"VersionStages": []string{vault.StageCurrent},
		})

	case "DescribeSecret":
		secretID, _ := body["SecretId"].(string)
		sec, err := s.store.GetSecret(caller, secretID, 0, "")
		if err != nil {
			writeAWSError(w, http.StatusBadRequest, "ResourceNotFoundException", err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ARN":             sec.ARN,
			"Name":            sec.Path,
			"Description":     sec.Description,
			"LastChangedDate": float64(sec.UpdatedAt.Unix()),
			"CreatedDate":     float64(sec.CreatedAt.Unix()),
		})

	case "DeleteSecret":
		secretID, _ := body["SecretId"].(string)
		if err := s.store.DeleteSecret(caller, secretID); err != nil {
			writeAWSError(w, http.StatusBadRequest, "ResourceNotFoundException", err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ARN":  fmt.Sprintf("arn:aws:secretsmanager:local:000000000000:secret:%s", vault.NormalizePath(secretID)),
			"Name": vault.NormalizePath(secretID),
		})

	default:
		writeAWSError(w, http.StatusBadRequest, "InvalidAction", "Unsupported SecretsManager operation: "+op)
	}
}

func writeAWSError(w http.ResponseWriter, status int, code string, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"__type":  code,
		"message": message,
	})
}
