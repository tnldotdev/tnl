// Package cliflags binds typed settings to pflag. Cobra owns command selection,
// help and completion; environment values apply only to the selected command.
package cliflags

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Bind registers the fields of a command's options or the server settings
// catalog. untagged fields are operation state and never become public flags.
func Bind(cmd *cobra.Command, options any, persistent bool) {
	if options == nil {
		return
	}
	flags := cmd.Flags()
	if persistent {
		flags = cmd.PersistentFlags()
	}
	var arguments []argument
	var walk func(reflect.Value)
	walk = func(v reflect.Value) {
		for i := range v.NumField() {
			field, value := v.Type().Field(i), v.Field(i)
			tag := field.Tag
			if _, ok := tag.Lookup("embed"); ok {
				walk(value)
				continue
			}
			if field.PkgPath != "" || tag == "" {
				continue
			}
			name := tag.Get("name")
			if name == "" {
				name = kebab(field.Name)
			}
			val := &setting{value: value, path: tag.Get("type") == "path"}
			if choices := tag.Get("enum"); choices != "" {
				val.choices = strings.Split(choices, ",")
			}
			usage := strings.ReplaceAll(tag.Get("help"), "${enum}", strings.Join(val.choices, ", "))
			if _, ok := tag.Lookup("arg"); ok {
				_, optional := tag.Lookup("optional")
				arguments = append(arguments, argument{name, tag.Get("env"), optional, val})
				if cmd.Annotations == nil {
					cmd.Annotations = make(map[string]string)
				}
				cmd.Annotations["cliflags:arg:"+name] = usage
				cmd.Annotations["cliflags:type:"+name] = val.Type()
				if val.path {
					cmd.Annotations["cliflags:type:"+name] = "path"
				}
				if len(val.choices) > 0 {
					cmd.Annotations["cliflags:enum:"+name] = tag.Get("enum")
				}
				if optional {
					cmd.Use += " [" + name + "]"
				} else {
					cmd.Use += " <" + name + ">"
				}
				continue
			}
			fallback, hasDefault := tag.Lookup("default")
			if hasDefault {
				if err := val.Set(fallback); err != nil {
					panic("invalid default for --" + name + ": " + err.Error())
				}
				val.declaredDefault = fallback
				val.replace = true
			}
			f := flags.VarPF(val, name, "", usage)
			if val.Type() == "bool" {
				f.NoOptDefVal = "true"
			}
			_, f.Hidden = tag.Lookup("hidden")
			f.Annotations = map[string][]string{}
			if key := tag.Get("env"); key != "" {
				f.Annotations["env"] = []string{key}
			}
			if _, ok := tag.Lookup("required"); ok {
				f.Annotations["required"] = []string{"true"}
			}
			if len(val.choices) > 0 {
				if err := cmd.RegisterFlagCompletionFunc(name, cobra.FixedCompletions(val.choices, cobra.ShellCompDirectiveNoFileComp)); err != nil {
					panic(err)
				}
			}
		}
	}
	walk(reflect.ValueOf(options).Elem())
	cmd.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) > len(arguments) {
			return errors.New("unexpected positional argument")
		}
		for i, arg := range arguments {
			raw := os.Getenv(arg.env)
			if i < len(args) {
				raw = args[i]
			} else if raw == "" {
				if arg.optional {
					continue
				}
				return fmt.Errorf("missing <%s>", arg.name)
			}
			if err := arg.val.Set(raw); err != nil {
				return err
			}
		}
		return Resolve(cmd.Flags())
	}
}

type argument struct {
	name, env string
	optional  bool
	val       *setting
}

// Resolve applies environment values after parsing, so flags take precedence
// and help never reads or prints credential values.
func Resolve(flags *pflag.FlagSet) error {
	var err error
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed || err != nil {
			return
		}
		if keys := f.Annotations["env"]; len(keys) != 0 {
			if raw, set := os.LookupEnv(keys[0]); set {
				err = f.Value.Set(raw)
				return
			}
		}
		if f.Annotations["required"] != nil {
			err = fmt.Errorf("missing --%s", f.Name)
		}
	})
	return err
}

type setting struct {
	value           reflect.Value
	path            bool
	choices         []string
	declaredDefault string
	replace         bool
}

// Help describes a declared input without consulting its current value.
type Help struct {
	Usage, Default string
	Choices        []string
	Path, Required bool
}

// Positional is a declared positional input in parser order.
type Positional struct {
	Name, Type           string
	Optional, Repeatable bool
	Help
}

// Positionals uses the same labels as the usage line. Bind appends its labels
// in field order; commands with custom Args can declare their labels in Use.
func Positionals(cmd *cobra.Command) []Positional {
	var arguments []Positional
	labels := strings.Fields(cmd.Use)
	if len(labels) < 2 {
		return arguments
	}
	for _, label := range labels[1:] {
		optional := strings.HasPrefix(label, "[") && strings.HasSuffix(label, "]")
		if !optional && !(strings.HasPrefix(label, "<") && strings.HasSuffix(label, ">")) {
			continue
		}
		name := label[1 : len(label)-1]
		meta, _ := ArgumentHelp(cmd, name)
		kind := cmd.Annotations["cliflags:type:"+name]
		if kind == "" {
			kind = "string"
		}
		name, repeatable := strings.CutSuffix(name, "...")
		arguments = append(arguments, Positional{
			Name: name, Type: kind, Optional: optional, Repeatable: repeatable, Help: meta,
		})
	}
	return arguments
}

// ArgumentHelp returns the metadata for a positional argument added by Bind.
func ArgumentHelp(cmd *cobra.Command, name string) (Help, bool) {
	usage, ok := cmd.Annotations["cliflags:arg:"+name]
	h := Help{Usage: usage}
	if enum := cmd.Annotations["cliflags:enum:"+name]; enum != "" {
		h.Choices = strings.Split(enum, ",")
	}
	return h, ok
}

// FlagHelp preserves the literal default, even for paths and durations.
func FlagHelp(f *pflag.Flag) Help {
	h := Help{Usage: f.Usage, Default: f.DefValue, Required: f.Annotations["required"] != nil || f.Annotations[cobra.BashCompOneRequiredFlag] != nil}
	if s, ok := f.Value.(*setting); ok {
		h.Default, h.Choices, h.Path = s.declaredDefault, s.choices, s.path
	}
	return h
}

func (s *setting) Type() string {
	if s == nil || !s.value.IsValid() {
		return "value"
	}
	t := s.value.Type()
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeFor[time.Duration]() {
		return "duration"
	}
	return t.Kind().String()
}

func (s *setting) String() string {
	if s == nil || !s.value.IsValid() {
		return ""
	}
	v := reflect.Indirect(s.value)
	if !v.IsValid() {
		return ""
	}
	return fmt.Sprint(v.Interface())
}

func (s *setting) Set(raw string) error {
	if len(s.choices) != 0 && !slices.Contains(s.choices, raw) {
		return fmt.Errorf("choose one of %s", strings.Join(s.choices, ", "))
	}
	v := s.value
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}
	if v.Type() == reflect.TypeFor[time.Duration]() {
		d, err := time.ParseDuration(raw)
		if err == nil {
			v.SetInt(int64(d))
		}
		return err
	}
	switch v.Kind() {
	case reflect.String:
		if s.path {
			raw = ExpandPath(raw)
		}
		v.SetString(raw)
	case reflect.Bool:
		x, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		v.SetBool(x)
	case reflect.Int, reflect.Int64:
		x, err := strconv.ParseInt(raw, 0, v.Type().Bits())
		if err != nil {
			return err
		}
		v.SetInt(x)
	case reflect.Uint64:
		x, err := strconv.ParseUint(raw, 0, 64)
		if err != nil {
			return err
		}
		v.SetUint(x)
	case reflect.Slice:
		if s.replace {
			v.SetZero()
			s.replace = false
		}
		for _, item := range splitValues(raw, ',') {
			if s.path {
				item = ExpandPath(item)
			}
			v.Set(reflect.Append(v, reflect.ValueOf(item)))
		}
	case reflect.Map:
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
		for _, pair := range splitValues(raw, ';') {
			key, rawValue, ok := strings.Cut(pair, "=")
			if !ok {
				return errors.New("expected KEY=VALUE")
			}
			item := reflect.New(v.Type().Elem()).Elem()
			if err := (&setting{value: item}).Set(rawValue); err != nil {
				return err
			}
			v.SetMapIndex(reflect.ValueOf(key), item)
		}
	default:
		return fmt.Errorf("unsupported setting type %s", v.Type())
	}
	return nil
}

func splitValues(s string, sep byte) []string {
	var out []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == sep {
			i++
		} else if s[i] == sep {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(s[i])
	}
	if b.Len() != 0 {
		out = append(out, b.String())
	}
	return out
}

func ExpandPath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	if strings.HasPrefix(path, "~/") {
		if u, err := user.Current(); err == nil {
			return filepath.Join(u.HomeDir, path[2:])
		}
	}
	if full, err := filepath.Abs(path); err == nil {
		return full
	}
	return path
}

func kebab(s string) string {
	var b strings.Builder
	for i, ch := range s {
		if i > 0 && ch >= 'A' && ch <= 'Z' && (s[i-1] >= 'a' && s[i-1] <= 'z' || i+1 < len(s) && s[i+1] >= 'a' && s[i+1] <= 'z') {
			b.WriteByte('-')
		}
		b.WriteRune(ch)
	}
	return strings.ToLower(b.String())
}
