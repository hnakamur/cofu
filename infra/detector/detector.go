package detector

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"

	"github.com/kohkimakimoto/cofu/infra/backend"
	"github.com/kohkimakimoto/cofu/infra/command"
)

type Detector func(*backend.Cmd) command.CommandFactory

var DefaultDetectors []Detector

func init() {
	DefaultDetectors = []Detector{
		DetectRedhat,
		DetectDebian,
		DetectDarwin,
		DetectUnknown,
	}
}

func DetectUnknown(c *backend.Cmd) command.CommandFactory {
	ret := &command.BaseCommand{}
	ret.SetOSFamily("unknown")
	ret.SetOSRelease("unknown")
	return ret
}

// inspired by https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/redhat.rb
func DetectRedhat(c *backend.Cmd) command.CommandFactory {
	if c.RunCommand("ls /etc/fedora-release").Success() {
		// fedora
		line := strings.TrimSpace(c.RunCommand("cat /etc/redhat-release").Stdout.String())
		matches := regexp.MustCompile(`release (\d[\d]*)`).FindStringSubmatch(line)
		var release string
		if len(matches) != 0 {
			release = matches[1]
		}

		ret := &command.FedoraCommand{}
		ret.SetOSFamily("fedora")
		ret.SetOSRelease(release)

		return ret

	} else if c.RunCommand("ls /etc/redhat-release").Success() {
		// redhat
		line := strings.TrimSpace(c.RunCommand("cat /etc/redhat-release").Stdout.String())
		matches := regexp.MustCompile(`release (\d[\d]*)`).FindStringSubmatch(line)
		var release string
		if len(matches) != 0 {
			release = matches[1]
		}

		var ret command.CommandFactory
		if release == "5" {
			ret = &command.RedhatV5Command{}
		} else if release == "7" {
			ret = &command.RedhatV7Command{}
		} else {
			ret = &command.RedhatCommand{}
		}

		ret.SetOSFamily("redhat")
		ret.SetOSRelease(release)
		return ret

	} else if c.RunCommand("ls /etc/system-release").Success() {
		// amazon
		line := strings.TrimSpace(c.RunCommand("cat /etc/system-release").Stdout.String())
		matches := regexp.MustCompile(`release (\d[\d]*)`).FindStringSubmatch(line)
		var release string
		if len(matches) != 0 {
			release = matches[1]
		}

		ret := &command.AmazonCommand{}
		ret.SetOSFamily("amazon")
		ret.SetOSRelease(release)
		return ret
	}

	return nil
}

func DetectDebian(c *backend.Cmd) command.CommandFactory {
	if c.RunCommand("ls /etc/debian_version").Success() {
		var distro string
		var release string
		cmdRes := c.RunCommand("lsb_release -ir")
		if cmdRes.Success() {
			scanner := bufio.NewScanner(&cmdRes.Stdout)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Distributor ID:") {
					words := strings.Split(line, ":")
					distro = strings.TrimSpace(words[len(words)-1])
				} else if strings.HasPrefix(line, "Release:") {
					words := strings.Split(line, ":")
					release = strings.TrimSpace(words[len(words)-1])
				}
			}
		} else {
			cmdRes = c.RunCommand("cat /etc/lsb-release")
			if cmdRes.Success() {
				scanner := bufio.NewScanner(&cmdRes.Stdout)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "DISTRIB_ID=") {
						words := strings.Split(line, ":")
						distro = strings.TrimSpace(words[len(words)-1])
					} else if strings.HasPrefix(line, "DISTRIB_RELEASE=") {
						words := strings.Split(line, ":")
						release = strings.TrimSpace(words[len(words)-1])
					}
				}
			}
		}
		if distro == "" {
			distro = "debian"
		}
		family := strings.ToLower(regexp.MustCompile(`[^[:alnum:]]`).ReplaceAllString(distro, ""))

		var ret command.CommandFactory
		if family == "debian" {
			intRelease, _ := strconv.ParseInt(release, 10, 64)
			if intRelease >= 8 {
				ret = &command.DebianV8Command{}
			} else {
				ret = &command.DebianV6Command{}
			}
		} else if family == "ubuntu" {
			if release >= "16.04" {
				ret = &command.UbuntuV1604Command{}
			} else {
				ret = &command.UbuntuV1204Command{}
			}
		}
		if ret != nil {
			ret.SetOSFamily(family)
			ret.SetOSRelease(release)
			return ret
		}
	}
	return nil
}

// inspired by https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/darwin.rb
func DetectDarwin(c *backend.Cmd) command.CommandFactory {
	r := regexp.MustCompile(`Darwin`)
	uname := c.RunCommand("uname -sr").Stdout.String()
	uname = strings.TrimSpace(uname)
	if r.MatchString(uname) {
		// darwin
		r = regexp.MustCompile(`([\d.]+)$`)
		matches := r.FindStringSubmatch(uname)
		ret := &command.DarwinCommand{}

		if len(matches) != 0 {
			ret.SetOSFamily("darwin")
			ret.SetOSRelease(matches[1])
		} else {
			ret.SetOSFamily("darwin")
			ret.SetOSRelease("")
		}

		return ret
	}
	return nil
}
