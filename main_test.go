package main

import "testing"

func TestSuggestSeparatorTypo(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "the actual typo: separator glued to the command",
			args: []string{"--claude"},
			want: "-- claude",
		},
		{
			name: "glued separator with trailing args preserved",
			args: []string{"--claude", "--resume"},
			want: "-- claude --resume",
		},
		{
			name: "a real known flag is not a typo",
			args: []string{"--net"},
			want: "",
		},
		{
			name: "a genuine flag form with = is not a glued command",
			args: []string{"--output=json"},
			want: "",
		},
		{
			name: "bare -- alone suggests nothing",
			args: []string{"--"},
			want: "",
		},
		{
			name: "no arguments at all",
			args: nil,
			want: "",
		},
		{
			name: "a plain command with no dashes is not this typo",
			args: []string{"claude"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := suggestSeparatorTypo(tt.args); got != tt.want {
				t.Errorf("suggestSeparatorTypo(%q) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}
