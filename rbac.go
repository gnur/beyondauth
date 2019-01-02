package main

import (
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/gnur/beyondauth/jwt"
	log "github.com/sirupsen/logrus"
	fsnotify "gopkg.in/fsnotify/fsnotify.v1"
)

// Conf is the basic config struct
type Conf struct {
	sync.RWMutex
	OAuth       oauthConf
	fqdn        string
	cookieScope string
	maxTokenAge string
	Groups      map[string]group
	Hosts       map[string]host
}

type oauthConf struct {
	clientID       string
	clientSecret   string
	providerDomain string
	nonce          string
}

type group struct {
	Subnets []cidr
	Domains []string
	Users   []string
}

type host struct {
	Public          bool
	MatchSubDomains bool
	AllowedGroups   []string
}

type cidr struct {
	net.IPNet
}

func (c *cidr) UnmarshalText(text []byte) error {
	_, subnet, err := net.ParseCIDR(string(text))
	c.IPNet = *subnet
	return err
}

func watchConfig(conf *BeyondauthConfig, path string) {
	log.Debug("Starting conf watcher")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("starting watcher loop")

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Create == fsnotify.Create && filepath.Base(event.Name) == "..data" {
					//kubernetes configmaps get updated like this
					loadConfig(conf, path)
				} else if event.Op&fsnotify.Write == fsnotify.Write && event.Name == path {
					//regular files get updated like this
					loadConfig(conf, path)
				}
			case err := <-watcher.Errors:
				log.Println("error:", err)
				return
			}
		}
	}()
	log.WithField("path", path).Debug("adding watcher")
	err = watcher.Add(filepath.Dir(path))
	if err != nil {
		log.Fatal(err)
	}
}
func loadConfig(conf *BeyondauthConfig, path string) error {
	log.WithField("path", path).Info("Loading config")
	var c BeyondauthConfig
	_, err := toml.DecodeFile(path, &c)
	if err != nil {
		log.WithField("err", err).Error("invalid config")
		return err
	}
	conf.Lock()
	conf.Groups = c.Groups
	conf.Hosts = c.Hosts
	conf.Unlock()
	return nil
}

func (rules *BeyondauthConfig) requestAllowed(r *http.Request) (allowed bool, user string) {
	var h host
	var ok bool
	var hostWithoutSub string

	host := r.Header.Get("x-forwarded-host")
	s := strings.SplitAfterN(host, ".", 2)
	if len(s) > 1 {
		hostWithoutSub = s[1]
	} else {
		hostWithoutSub = host
	}

	if h, ok = rules.Hosts[host]; !ok {
		if h, ok = rules.Hosts[hostWithoutSub]; !ok || !h.MatchSubDomains {
			log.WithFields(log.Fields{
				"host":    host,
				"allowed": false,
			}).Debug("host not found")
			return false, ""
		}
	}

	if h.Public {
		return true, ""
	}

	ipHeader := r.Header.Get("x-forwarded-for")
	ip := net.ParseIP(ipHeader)
	if ip == nil {
		log.WithFields(log.Fields{
			"header":  ipHeader,
			"allowed": false,
		}).Debug("invalid ip in header")
		return false, ""
	}

	c, err := r.Cookie("x-beyond-auth")
	if err == nil {
		user, err = jwt.ValidateToken(c.Value)
		if err != nil {
			log.WithFields(log.Fields{
				"error":   err,
				"allowed": false,
			}).Debug("could not validate cookie JWT")
		}
	}

	groups := getMatchedGroups(rules.Groups, ip, user)

	if hasMatch(h.AllowedGroups, groups) {
		log.WithFields(log.Fields{
			"allowed": true,
		}).Debug("user in valid group")
		return true, user
	}
	return false, ""
}

func hasMatch(a, b []string) bool {
	for _, i := range a {
		for _, a := range b {
			if i == a {
				return true
			}
		}
	}
	return false
}

func getMatchedGroups(matchGroups map[string]group, ip net.IP, user string) []string {
	l := log.WithFields(log.Fields{
		"ip":   ip,
		"user": user,
	})
	var groups []string
	for name, group := range matchGroups {
		if validUser(user, group.Users) || validDomain(user, group.Domains) || validIP(ip, group.Subnets) {
			l.WithField("group", name).Debug("adding to group")
			groups = append(groups, name)
			continue
		}
	}
	return groups

}

func validIP(ip net.IP, list []cidr) bool {
	for _, b := range list {
		if b.Contains(ip) {
			return true
		}
	}
	return false
}
func validDomain(a string, list []string) bool {
	for _, b := range list {
		if strings.HasSuffix(a, b) {
			return true
		}
	}
	return false
}

func validUser(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
