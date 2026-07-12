package selection

import "testing"

func TestMatchPortableGlobsAndPathValidation(t *testing.T) {
	for _, test := range []struct {
		pattern string
		name    string
		want    bool
	}{
		{pattern: "*.txt", name: "report.txt", want: true},
		{pattern: "*.txt", name: "nested/report.txt", want: false},
		{pattern: "**/*.txt", name: "nested/deep/report.txt", want: true},
		{pattern: "src/**/main.go", name: "src/main.go", want: true},
		{pattern: "src/**/main.go", name: "src/a/b/main.go", want: true},
		{pattern: "**/**/**/target", name: "a/b/c/target", want: true},
	} {
		got, err := Match(test.pattern, test.name)
		if err != nil || got != test.want {
			t.Fatalf("Match(%q, %q) = %t, %v; want %t, nil", test.pattern, test.name, got, err, test.want)
		}
	}
	for _, test := range []struct{ pattern, name string }{
		{pattern: "../secret", name: "secret"},
		{pattern: "/absolute", name: "absolute"},
		{pattern: `nested\\file`, name: "nested/file"},
		{pattern: "**", name: "../escape"},
	} {
		if _, err := Match(test.pattern, test.name); err == nil {
			t.Fatalf("Match(%q, %q) accepted an unsafe path", test.pattern, test.name)
		}
	}
}
