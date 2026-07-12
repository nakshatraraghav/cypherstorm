package cli

import (
	"context"
	"io"

	"github.com/nakshatraraghav/cypherstorm/internal/app"
	configpkg "github.com/nakshatraraghav/cypherstorm/internal/config"
	"github.com/nakshatraraghav/cypherstorm/internal/report"
	"github.com/spf13/cobra"
)

type Service interface {
	Protect(context.Context, app.ProtectRequest, app.EventSink) (app.ProtectResult, error)
	Restore(context.Context, app.RestoreRequest, app.EventSink) (app.RestoreResult, error)
	Hash(context.Context, app.HashRequest, app.EventSink) ([]app.HashResult, error)
	Benchmark(context.Context, app.BenchmarkRequest, app.EventSink) (report.Report, error)
	Inspect(context.Context, app.InspectRequest, app.EventSink) (app.InspectResult, error)
	Verify(context.Context, app.VerifyRequest, app.EventSink) (app.VerifyResult, error)
	List(context.Context, app.ListRequest, app.EventSink) (app.ListResult, error)
	KeyGenerate(context.Context, app.KeyGenerateRequest, app.EventSink) (app.KeyResult, error)
	KeyValidate(context.Context, string) (app.KeyResult, error)
	KeyFingerprint(context.Context, string) (app.KeyResult, error)
	CredentialAdd(context.Context, string, app.Credential) (app.CredentialDescriptor, error)
	CredentialList(context.Context) ([]app.CredentialDescriptor, error)
	CredentialInspect(context.Context, string) (app.CredentialDescriptor, error)
	CredentialRemove(context.Context, string) error
	ResolveSavedCredential(context.Context, string) (app.Credential, error)
	ConfigShow(context.Context, bool) (app.ConfigResult, error)
	ConfigValidate(context.Context) (app.ConfigResult, error)
	PolicyShow(context.Context, string) (configpkg.Policy, error)
	BatchProtect(context.Context, app.BatchProtectRequest, app.EventSink) (app.BatchResult, error)
	BatchRestore(context.Context, app.BatchRestoreRequest, app.EventSink) (app.BatchResult, error)
	ManifestCreate(context.Context, string, string) (app.Manifest, error)
	ManifestVerify(context.Context, string, string) (app.CompareResult, error)
	Compare(context.Context, string, string) (app.CompareResult, error)
	Recommend(context.Context, app.RecommendRequest, app.EventSink) (app.RecommendResult, error)
	IdentityGenerate(context.Context, string, string) (app.IdentityResult, error)
	IdentityPublic(context.Context, string, string) (app.IdentityResult, error)
	IdentityFingerprint(context.Context, string) (app.IdentityResult, error)
	Sign(context.Context, string, string, string, string) (app.SignatureResult, error)
	SignatureInspect(context.Context, string) (app.SignatureResult, error)
	SignatureVerify(context.Context, string, string, string) (app.SignatureResult, error)
	Rekey(context.Context, app.RekeyRequest, app.EventSink) (app.RekeyResult, error)
	IdentityQR(context.Context, string, string) (app.QRResult, error)
	RecipientImportQR(context.Context, string, string) (app.QRResult, error)
}

type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

type RootOptions struct {
	Interactive bool
	RunTUI      func(context.Context) error
}

func NewRoot(service Service, streams Streams, version string) *cobra.Command {
	return NewRootWithOptions(service, streams, version, RootOptions{})
}

func NewRootWithOptions(service Service, streams Streams, version string, options RootOptions) *cobra.Command {
	root := &cobra.Command{
		Use:           "cypherstorm",
		Short:         "Protect, restore, hash, and benchmark files safely",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if options.Interactive && options.RunTUI != nil {
				return options.RunTUI(command.Context())
			}
			return command.Help()
		},
	}
	root.SetIn(streams.In)
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	root.PersistentFlags().String("output-format", "text", "output format: text or json")
	root.PersistentFlags().String("progress", "auto", "progress mode: auto, none, text, or json")
	root.AddCommand(
		newProtectCommand(service, streams),
		newRestoreCommand(service, streams),
		newHashCommand(service),
		newBenchmarkCommand(service),
		newInspectCommand(service, streams),
		newVerifyCommand(service, streams),
		newListCommand(service, streams),
		newKeyCommand(service),
		newCredentialCommand(service, streams),
		newConfigCommand(service),
		newPolicyCommand(service),
		newBatchCommand(service, streams),
		newManifestCommand(service),
		newCompareCommand(service),
		newRecommendCommand(service),
		newIdentityCommand(service),
		newSignCommand(service),
		newSignatureCommand(service),
		newRekeyCommand(service, streams),
		newRecipientCommand(service),
		newVersionCommand(version),
	)
	root.AddCommand(newCompletionCommand(root), newDocsCommand(root))
	if options.RunTUI != nil {
		root.AddCommand(&cobra.Command{
			Use:   "tui",
			Short: "Launch the interactive terminal interface",
			Args:  cobra.NoArgs,
			RunE: func(command *cobra.Command, _ []string) error {
				return options.RunTUI(command.Context())
			},
		})
	}
	return root
}
