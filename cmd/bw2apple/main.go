package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/oliharper/bitwarden-to-apple-passwords/internal/verifier"

	"github.com/urfave/cli/v3"
)

var errInput = errors.New("invalid source, case, or request")

func distinct(paths ...string) bool {
	seen := map[string]bool{}
	for _, path := range paths {
		if path == "" {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return false
		}
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			abs = resolved
		}
		if seen[abs] {
			return false
		}
		seen[abs] = true
	}
	return true
}

func noArguments(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 0 {
		return errInput
	}
	return nil
}

func action(result *any, run func(*cli.Command) (any, error)) cli.ActionFunc {
	return func(_ context.Context, cmd *cli.Command) error {
		var err error
		*result, err = run(cmd)
		return err
	}
}

func commands(result *any) *cli.Command {
	safeUsageError := func(context.Context, *cli.Command, error, bool) error { return errInput }
	return &cli.Command{
		Name:         "bw2apple",
		Usage:        "Build and inspect a private evidence case",
		ErrWriter:    io.Discard,
		OnUsageError: safeUsageError,
		Action:       func(context.Context, *cli.Command) error { return errInput },
		Commands: []*cli.Command{
			{
				Name:                      "compare",
				Usage:                     "Compare Bitwarden and Apple Passwords exports",
				DisableSliceFlagSeparator: true,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "bitwarden", Usage: "Bitwarden personal JSON export", Required: true},
					&cli.StringFlag{Name: "apple", Usage: "Apple Passwords CSV", Required: true},
					&cli.StringFlag{Name: "case", Usage: "New private case directory", Required: true},
					&cli.StringSliceFlag{Name: "note", Usage: "Optional UTF-8 text file; repeatable"},
				},
				ArgValidator: noArguments,
				OnUsageError: safeUsageError,
				Action:       action(result, compare),
			},
			{
				Name:  "report",
				Usage: "Inspect an evidence case",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "case", Usage: "Evidence case", Required: true},
					&cli.StringFlag{Name: "view", Usage: "summary, records, fields, groups, absent-passwords, notes, matches, occurrences, coverage, limits, annotations", Value: "summary"},
					&cli.StringFlag{Name: "record", Usage: "Record reference"},
					&cli.StringFlag{Name: "field", Usage: "Field reference"},
					&cli.StringFlag{Name: "query", Usage: "Metadata query"},
					&cli.StringFlag{Name: "domain", Usage: "Exact base domain filter"},
					&cli.StringFlag{Name: "username", Usage: "Exact username filter"},
				},
				ArgValidator: noArguments,
				OnUsageError: safeUsageError,
				Action:       action(result, report),
			},
			{
				Name:  "annotate",
				Usage: "Add a user-provenance reference annotation",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "case", Usage: "Evidence case", Required: true},
					&cli.StringFlag{Name: "input", Usage: "Annotation JSON", Required: true},
				},
				ArgValidator: noArguments,
				OnUsageError: safeUsageError,
				Action:       action(result, annotate),
			},
			{
				Name:  "history-export",
				Usage: "Export readable Bitwarden history",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "bitwarden", Usage: "Bitwarden personal JSON export", Required: true},
					&cli.StringFlag{Name: "output", Usage: "New private text archive", Required: true},
					&cli.StringFlag{Name: "timezone", Usage: "IANA display time zone", Value: "UTC"},
				},
				ArgValidator: noArguments,
				OnUsageError: safeUsageError,
				Action:       action(result, historyExport),
			},
		},
	}
}

func compare(cmd *cli.Command) (any, error) {
	bitwardenPath, applePath, casePath := cmd.String("bitwarden"), cmd.String("apple"), cmd.String("case")
	notes := cmd.StringSlice("note")
	if bitwardenPath == "" || applePath == "" || casePath == "" ||
		!distinct(append([]string{bitwardenPath, applePath, casePath}, notes...)...) {
		return nil, errInput
	}

	if err := verifier.PreflightNewCase(casePath); err != nil {
		return nil, err
	}

	caseData, err := verifier.LoadCase(bitwardenPath, applePath, notes)
	if err != nil {
		return nil, err
	}
	ledger, err := verifier.CreateLedger(casePath)
	if err != nil {
		return nil, err
	}
	defer ledger.Close()

	success := false
	defer func() {
		if !success {
			ledger.Abort()
		}
	}()

	if err = ledger.Write(verifier.Compare(caseData)); err != nil {
		return nil, err
	}

	if err = ledger.Finalize(); err != nil {
		return nil, err
	}

	result, err := ledger.Summary()
	if err != nil {
		return nil, err
	}
	success = true
	return result, nil
}

func report(cmd *cli.Command) (any, error) {
	casePath, view := cmd.String("case"), cmd.String("view")
	if casePath == "" {
		return nil, errInput
	}
	if (view == "fields" && cmd.String("record") == "") ||
		((view == "matches" || view == "occurrences") && cmd.String("field") == "") {
		return nil, errInput
	}

	ledger, err := verifier.OpenLedger(casePath, true)
	if err != nil {
		return nil, err
	}
	defer ledger.Close()

	switch view {
	case "summary":
		return ledger.Summary()
	case "records":
		return ledger.Records(cmd.String("query"))
	case "fields":
		return ledger.Fields(cmd.String("record"))
	case "groups":
		return ledger.Groups(cmd.String("domain"), cmd.String("username"))
	case "absent-passwords":
		return ledger.AbsentPasswords()
	case "notes":
		return ledger.Notes()
	case "matches":
		return ledger.Matches(cmd.String("field"))
	case "occurrences":
		return ledger.Occurrences(cmd.String("field"))
	case "coverage":
		return ledger.Coverage()
	case "limits":
		return ledger.Limits()
	case "annotations":
		return ledger.Annotations()
	default:
		return nil, errInput
	}
}

func annotate(cmd *cli.Command) (any, error) {
	casePath, input := cmd.String("case"), cmd.String("input")
	if casePath == "" || input == "" {
		return nil, errInput
	}

	request, err := verifier.ReadAnnotation(input)
	if err != nil {
		return nil, err
	}

	ledger, err := verifier.OpenLedger(casePath, false)
	if err != nil {
		return nil, err
	}
	defer ledger.Close()
	return ledger.ApplyAnnotation(request)
}

func historyExport(cmd *cli.Command) (any, error) {
	bitwardenPath, outputPath := cmd.String("bitwarden"), cmd.String("output")
	if bitwardenPath == "" || outputPath == "" || !distinct(bitwardenPath, outputPath) {
		return nil, errInput
	}
	return verifier.HistoryExport(bitwardenPath, outputPath, cmd.String("timezone"))
}

func runWithOutput(args []string, output io.Writer) (any, error) {
	var result any
	var frameworkOutput bytes.Buffer
	app := commands(&result)
	app.Writer = &frameworkOutput
	if err := app.Run(context.Background(), append([]string{"bw2apple"}, args...)); err != nil {
		if errors.Is(err, verifier.ErrIncompatibleSchema) {
			return nil, err
		}
		return nil, errInput
	}
	if result == nil {
		if _, err := io.Copy(output, &frameworkOutput); err != nil {
			return nil, errInput
		}
	}
	return result, nil
}

func main() {
	result, err := runWithOutput(os.Args[1:], os.Stdout)
	if err != nil {
		if errors.Is(err, verifier.ErrIncompatibleSchema) {
			fmt.Fprintln(os.Stderr, "Verification stopped: incompatible case schema. No raw values were printed.")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "Verification stopped: invalid source, case, or request. No raw values were printed.")
		os.Exit(2)
	}
	if result == nil {
		return
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Verification stopped: unexpected processing failure. No raw values were printed.")
		os.Exit(2)
	}
	fmt.Println(string(encoded))
}
