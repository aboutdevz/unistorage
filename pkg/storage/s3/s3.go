package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const (
	// MultipartThreshold is 16MB per requirements.
	MultipartThreshold int64 = 16 * 1024 * 1024
	// DefaultPartSize is 16MB per chunk.
	DefaultPartSize int64 = 16 * 1024 * 1024
)

// Config holds S3 client connection settings.
type Config struct {
	Endpoint     string
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	UsePathStyle bool
	RetryConfig  RetryConfig
}

// Driver implements storage.Driver and storage.AdvancedDriver for S3-compatible object storage.
type Driver struct {
	client   *awss3.Client
	bucket   string
	retryCfg RetryConfig
}

// New creates an S3 driver instance configured with AWS SDK v2.
func New(ctx context.Context, cfg Config) (*Driver, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3: bucket name is required")
	}

	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	retryCfg := cfg.RetryConfig
	if retryCfg.MaxRetries == 0 {
		retryCfg = DefaultRetryConfig()
	}

	var optFns []func(*awsconfig.LoadOptions) error
	optFns = append(optFns, awsconfig.WithRegion(region))

	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		optFns = append(optFns, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("s3: failed to load aws config: %w", err)
	}

	s3Client := awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.UsePathStyle
	})

	return &Driver{
		client:   s3Client,
		bucket:   cfg.Bucket,
		retryCfg: retryCfg,
	}, nil
}

// NewWithClient creates an S3 driver using a pre-configured S3 client (ideal for testing).
func NewWithClient(client *awss3.Client, bucket string, retryCfg ...RetryConfig) *Driver {
	rCfg := DefaultRetryConfig()
	if len(retryCfg) > 0 {
		rCfg = retryCfg[0]
	}
	return &Driver{
		client:   client,
		bucket:   bucket,
		retryCfg: rCfg,
	}
}

// Name returns "s3".
func (d *Driver) Name() string {
	return "s3"
}

func (d *Driver) cleanKey(k string) string {
	cleaned := strings.TrimPrefix(strings.ReplaceAll(k, "\\", "/"), "/")
	return cleaned
}

// Read opens the object stream from S3.
func (d *Driver) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	key := d.cleanKey(path)
	var out *awss3.GetObjectOutput

	err := ExecuteWithRetry(ctx, d.retryCfg, func() error {
		var getErr error
		out, getErr = d.client.GetObject(ctx, &awss3.GetObjectInput{
			Bucket: aws.String(d.bucket),
			Key:    aws.String(key),
		})
		return getErr
	})

	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			code := apiErr.ErrorCode()
			if code == "NoSuchKey" || code == "NotFound" {
				return nil, &storage.StorageError{Op: "read", Driver: "s3", Path: path, Err: storage.ErrNotFound}
			}
		}
		return nil, &storage.StorageError{Op: "read", Driver: "s3", Path: path, Err: err}
	}

	return out.Body, nil
}

// Write uploads data from r into S3. Automatically triggers multipart upload if size > 16MB.
func (d *Driver) Write(ctx context.Context, path string, r io.Reader, size int64) error {
	return d.WriteWithOptions(ctx, path, r, size)
}

// WriteWithOptions uploads data with custom options and multipart handling.
func (d *Driver) WriteWithOptions(ctx context.Context, path string, r io.Reader, size int64, opts ...storage.WriteOption) error {
	key := d.cleanKey(path)
	options := storage.DefaultWriteOptions()
	for _, opt := range opts {
		opt(&options)
	}

	// Overwrite check if disabled
	if !options.Overwrite {
		_, err := d.Stat(ctx, path)
		if err == nil {
			return &storage.StorageError{Op: "write", Driver: "s3", Path: path, Err: storage.ErrAlreadyExists}
		}
	}

	// Case 1: Known size <= 16MB -> Single PutObject
	if size >= 0 && size <= MultipartThreshold {
		data := make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil && !errors.Is(err, io.EOF) {
			return &storage.StorageError{Op: "write", Driver: "s3", Path: path, Err: err}
		}
		return d.putSingleObject(ctx, key, data, options)
	}

	// Case 2: Known size > 16MB -> Multipart upload
	if size > MultipartThreshold {
		return d.uploadMultipart(ctx, key, r, size, options)
	}

	// Case 3: Unknown size (size < 0) -> Dynamic buffer up to 16MB
	buf := make([]byte, MultipartThreshold)
	n, err := io.ReadFull(r, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF || (err == nil && int64(n) < MultipartThreshold) {
		// Content fits completely in single part
		return d.putSingleObject(ctx, key, buf[:n], options)
	}
	if err != nil {
		return &storage.StorageError{Op: "write", Driver: "s3", Path: path, Err: err}
	}

	// Exceeded 16MB: Stream remaining using multipart
	combinedReader := io.MultiReader(bytes.NewReader(buf[:n]), r)
	return d.uploadMultipart(ctx, key, combinedReader, -1, options)
}

func (d *Driver) putSingleObject(ctx context.Context, key string, data []byte, options storage.WriteOptions) error {
	return ExecuteWithRetry(ctx, d.retryCfg, func() error {
		input := &awss3.PutObjectInput{
			Bucket: aws.String(d.bucket),
			Key:    aws.String(key),
			Body:   bytes.NewReader(data),
		}
		if options.ContentType != "" {
			input.ContentType = aws.String(options.ContentType)
		}
		if len(options.Metadata) > 0 {
			input.Metadata = options.Metadata
		}
		_, err := d.client.PutObject(ctx, input)
		return err
	})
}

func (d *Driver) uploadMultipart(ctx context.Context, key string, r io.Reader, totalSize int64, options storage.WriteOptions) error {
	// 1. Initiate multipart upload
	var uploadID string
	err := ExecuteWithRetry(ctx, d.retryCfg, func() error {
		createInput := &awss3.CreateMultipartUploadInput{
			Bucket: aws.String(d.bucket),
			Key:    aws.String(key),
		}
		if options.ContentType != "" {
			createInput.ContentType = aws.String(options.ContentType)
		}
		if len(options.Metadata) > 0 {
			createInput.Metadata = options.Metadata
		}
		out, err := d.client.CreateMultipartUpload(ctx, createInput)
		if err != nil {
			return err
		}
		uploadID = *out.UploadId
		return nil
	})
	if err != nil {
		return &storage.StorageError{Op: "write", Driver: "s3", Path: key, Err: fmt.Errorf("failed to initiate multipart upload: %w", err)}
	}

	// Guarantee abort on error
	completed := false
	defer func() {
		if !completed {
			abortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = d.client.AbortMultipartUpload(abortCtx, &awss3.AbortMultipartUploadInput{
				Bucket:   aws.String(d.bucket),
				Key:      aws.String(key),
				UploadId: aws.String(uploadID),
			})
		}
	}()

	// 2. Read and upload parts
	var completedParts []s3types.CompletedPart
	partNum := int32(1)
	partBuf := make([]byte, DefaultPartSize)

	for {
		n, readErr := io.ReadFull(r, partBuf)
		if n > 0 {
			partData := make([]byte, n)
			copy(partData, partBuf[:n])

			currentPartNum := partNum
			var partETag string

			uploadErr := ExecuteWithRetry(ctx, d.retryCfg, func() error {
				upOut, err := d.client.UploadPart(ctx, &awss3.UploadPartInput{
					Bucket:     aws.String(d.bucket),
					Key:        aws.String(key),
					UploadId:   aws.String(uploadID),
					PartNumber: aws.Int32(currentPartNum),
					Body:       bytes.NewReader(partData),
				})
				if err != nil {
					return err
				}
				partETag = *upOut.ETag
				return nil
			})
			if uploadErr != nil {
				return &storage.StorageError{Op: "write", Driver: "s3", Path: key, Err: fmt.Errorf("failed to upload part %d: %w", currentPartNum, uploadErr)}
			}

			completedParts = append(completedParts, s3types.CompletedPart{
				PartNumber: aws.Int32(currentPartNum),
				ETag:       aws.String(partETag),
			})
			partNum++
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return &storage.StorageError{Op: "write", Driver: "s3", Path: key, Err: fmt.Errorf("reading multipart stream failed: %w", readErr)}
		}
	}

	// 3. Complete multipart upload
	err = ExecuteWithRetry(ctx, d.retryCfg, func() error {
		_, completeErr := d.client.CompleteMultipartUpload(ctx, &awss3.CompleteMultipartUploadInput{
			Bucket:   aws.String(d.bucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
			MultipartUpload: &s3types.CompletedMultipartUpload{
				Parts: completedParts,
			},
		})
		return completeErr
	})
	if err != nil {
		return &storage.StorageError{Op: "write", Driver: "s3", Path: key, Err: fmt.Errorf("failed to complete multipart upload: %w", err)}
	}

	completed = true
	return nil
}

// List lists objects in the S3 bucket matching prefix.
func (d *Driver) List(ctx context.Context, prefix string) ([]storage.ObjectInfo, error) {
	res, err := d.ListWithOptions(ctx, storage.ListOptions{Prefix: prefix, Recursive: true})
	if err != nil {
		return nil, err
	}
	return res.Objects, nil
}

// ListWithOptions lists objects with pagination and continuation token.
func (d *Driver) ListWithOptions(ctx context.Context, opts storage.ListOptions) (*storage.ListResult, error) {
	keyPrefix := d.cleanKey(opts.Prefix)

	input := &awss3.ListObjectsV2Input{
		Bucket: aws.String(d.bucket),
	}
	if keyPrefix != "" {
		input.Prefix = aws.String(keyPrefix)
	}
	if opts.MaxKeys > 0 {
		maxK := opts.MaxKeys
		if maxK > 10000 {
			maxK = 10000
		}
		// #nosec G115 -- MaxKeys is capped and safe to convert
		input.MaxKeys = aws.Int32(int32(maxK))
	}
	if opts.ContinuationToken != "" {
		input.ContinuationToken = aws.String(opts.ContinuationToken)
	}
	if !opts.Recursive && opts.Delimiter != "" {
		input.Delimiter = aws.String(opts.Delimiter)
	} else if !opts.Recursive {
		input.Delimiter = aws.String("/")
	}

	var out *awss3.ListObjectsV2Output
	err := ExecuteWithRetry(ctx, d.retryCfg, func() error {
		var listErr error
		out, listErr = d.client.ListObjectsV2(ctx, input)
		return listErr
	})
	if err != nil {
		return nil, &storage.StorageError{Op: "list", Driver: "s3", Path: opts.Prefix, Err: err}
	}

	var results []storage.ObjectInfo
	for _, obj := range out.Contents {
		k := aws.ToString(obj.Key)
		modTime := time.Time{}
		if obj.LastModified != nil {
			modTime = obj.LastModified.UTC()
		}
		etag := strings.Trim(aws.ToString(obj.ETag), "\"")
		results = append(results, storage.ObjectInfo{
			Key:     k,
			Path:    k,
			Size:    aws.ToInt64(obj.Size),
			ModTime: modTime,
			IsDir:   strings.HasSuffix(k, "/"),
			ETag:    etag,
		})
	}

	// Add common prefixes (virtual directories)
	for _, cp := range out.CommonPrefixes {
		p := aws.ToString(cp.Prefix)
		results = append(results, storage.ObjectInfo{
			Key:   p,
			Path:  p,
			IsDir: true,
		})
	}

	var nextToken string
	if out.NextContinuationToken != nil {
		nextToken = *out.NextContinuationToken
	}

	return &storage.ListResult{
		Objects:               results,
		NextContinuationToken: nextToken,
		IsTruncated:           aws.ToBool(out.IsTruncated),
	}, nil
}

// Delete removes an object from the S3 bucket. Idempotent.
func (d *Driver) Delete(ctx context.Context, path string) error {
	key := d.cleanKey(path)
	err := ExecuteWithRetry(ctx, d.retryCfg, func() error {
		_, delErr := d.client.DeleteObject(ctx, &awss3.DeleteObjectInput{
			Bucket: aws.String(d.bucket),
			Key:    aws.String(key),
		})
		return delErr
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "NoSuchKey" || apiErr.ErrorCode() == "NotFound" {
				return nil
			}
		}
		return &storage.StorageError{Op: "delete", Driver: "s3", Path: path, Err: err}
	}
	return nil
}

// Stat returns metadata for an object in S3.
func (d *Driver) Stat(ctx context.Context, path string) (*storage.ObjectInfo, error) {
	key := d.cleanKey(path)
	var out *awss3.HeadObjectOutput

	err := ExecuteWithRetry(ctx, d.retryCfg, func() error {
		var headErr error
		out, headErr = d.client.HeadObject(ctx, &awss3.HeadObjectInput{
			Bucket: aws.String(d.bucket),
			Key:    aws.String(key),
		})
		return headErr
	})

	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			code := apiErr.ErrorCode()
			if code == "NotFound" || code == "NoSuchKey" || code == "404" {
				return nil, &storage.StorageError{Op: "stat", Driver: "s3", Path: path, Err: storage.ErrNotFound}
			}
		}
		// S3 HeadObject returns 404 as a generic error
		if strings.Contains(err.Error(), "404") || strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, &storage.StorageError{Op: "stat", Driver: "s3", Path: path, Err: storage.ErrNotFound}
		}
		return nil, &storage.StorageError{Op: "stat", Driver: "s3", Path: path, Err: err}
	}

	modTime := time.Time{}
	if out.LastModified != nil {
		modTime = out.LastModified.UTC()
	}

	etag := strings.Trim(aws.ToString(out.ETag), "\"")
	contentType := aws.ToString(out.ContentType)

	return &storage.ObjectInfo{
		Key:         key,
		Path:        key,
		Size:        aws.ToInt64(out.ContentLength),
		ModTime:     modTime,
		IsDir:       false,
		ETag:        etag,
		ContentType: contentType,
		Metadata:    out.Metadata,
	}, nil
}

// Stream reads the S3 object and writes directly to w using constant-memory pooled buffer.
func (d *Driver) Stream(ctx context.Context, path string, w io.Writer) error {
	rc, err := d.Read(ctx, path)
	if err != nil {
		return err
	}
	defer rc.Close()

	_, err = storage.StreamCopy(w, rc)
	return err
}

// Verify interface compliance at compile time.
var _ storage.Driver = (*Driver)(nil)
var _ storage.AdvancedDriver = (*Driver)(nil)
