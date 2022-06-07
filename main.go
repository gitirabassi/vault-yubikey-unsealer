package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	vapi "github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Recipients       []string `yaml:"recipients"`
	Identity         string   `yaml:"identity"`
	VaultAddress     string   `yaml:"vault_address"`
	UnsealKeyPath    string   `yaml:"recovery_keys_path"`
	RootTokenPath    string   `yaml:"root_token_path"`
	InitKeyShares    int      `yaml:"init_key_shares"`
	InitKeyThreshold int      `yaml:"init_key_threshold"`
	BinariesPath     string   `yaml:"binaries_path"`
}

type UnsealKeysStorage struct {
	Keys []string `yaml:"keys"`
}

var help bool

func init() {
	flag.BoolVar(&help, "help", false, "run ")
}

func main() {
	flag.Parse()

	rawConf, err := ioutil.ReadFile("/config.yaml")
	if err != nil {
		log.Fatalln(err)
	}
	conf := &Config{}
	err = yaml.Unmarshal(rawConf, conf)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	fmt.Println(conf)

	if help {
		log.Println("Running vault-manager!")
		rageV, err := exec.Command(filepath.Join(conf.BinariesPath, "rage"), "--version").Output()
		if err != nil {
			log.Fatalln(err)
		}
		log.Println(string(rageV))
		pluginV, err := exec.Command(filepath.Join(conf.BinariesPath, "age-plugin-yubikey"), "--version").Output()
		if err != nil {
			log.Fatalln(err)
		}
		log.Println(string(pluginV))
		pluginIdentities, err := exec.Command(filepath.Join(conf.BinariesPath, "age-plugin-yubikey"), "-i").Output()
		if err != nil {
			log.Fatalln(err)
		}
		log.Println(string(pluginIdentities))
		os.Exit(0)
	}

	for {
		err = checkInit(conf)
		if err != nil {
			log.Fatalln(err)
		}
		err = checkSealStatus(conf)
		if err != nil {
			log.Fatalln(err)
		}
		time.Sleep(60 * time.Second)
	}
}

func checkInit(conf *Config) error {
	c := &vapi.Config{
		Address: conf.VaultAddress,
		Timeout: 5 * time.Second,
	}
	cli, err := vapi.NewClient(c)
	if err != nil {
		return err
	}
	initialized, err := cli.Sys().InitStatus()
	if err != nil {
		return err
	}
	if initialized {
		log.Println("Vault is already initialized...")
		return nil
	}
	resp, err := cli.Sys().Init(&vapi.InitRequest{
		SecretShares:    conf.InitKeyShares,
		SecretThreshold: conf.InitKeyThreshold,
	})
	if err != nil {
		return err
	}
	log.Println("Vault has been initialized!")
	storage := &UnsealKeysStorage{
		Keys: resp.KeysB64,
	}
	err = conf.EncryptData(storage, conf.UnsealKeyPath)
	if err != nil {
		return err
	}
	log.Println("Unseal keys were stored in ", conf.UnsealKeyPath)
	err = conf.Encrypt(resp.RootToken, conf.RootTokenPath)
	if err != nil {
		return err
	}
	log.Println("Root token has been stored in ", conf.RootTokenPath)
	return nil
}

func checkSealStatus(conf *Config) error {
	c := &vapi.Config{
		Address: conf.VaultAddress,
		Timeout: 5 * time.Second,
	}
	cli, err := vapi.NewClient(c)
	if err != nil {
		return err
	}
	log.Println("Vault client was created successfully")
	resp, err := cli.Sys().SealStatus()
	if err != nil {
		return err
	}
	if !resp.Initialized {
		log.Println("We're trying to unseal but the Cluster hasn't been initialized yet")
		return nil
	}
	if !resp.Sealed {
		log.Println("Vault already unsealed!")
	}
	log.Println("Vault is sealed, tyring to useal now!")
	unsealKeys := &UnsealKeysStorage{}
	err = conf.DecryptData(unsealKeys, conf.UnsealKeyPath)
	if err != nil {
		return err
	}
	log.Println("Unseal keys were successfully decrypted!")
	for _, v := range unsealKeys.Keys {
		resp, err := cli.Sys().SealStatus()
		if err != nil {
			return err
		}
		if !resp.Sealed {
			log.Println("Vault is unseled!!")
			break
		}
		un, err := cli.Sys().Unseal(v)
		if err != nil {
			return err
		}
		if resp.Progress < un.Progress {
			log.Println("We're making progress unsealing vault!")
		} else {
			log.Println("We're NOT making progress", un)
		}
		log.Println("moving to next unseal key...")
	}
	return nil
}

func (c *Config) EncryptData(data interface{}, path string) error {
	output, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	return c.Encrypt(string(output), path)
}

func (c *Config) DecryptData(data interface{}, path string) error {
	rawData, err := c.Decrypt(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal([]byte(rawData), data)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) Encrypt(data, path string) error {
	args := []string{}
	args = append(args, "--encrypt", "--armor")
	args = append(args, "--output", path)
	for _, v := range c.Recipients {
		args = append(args, "--recipient")
		args = append(args, v)
	}
	cmd := exec.Command(filepath.Join(c.BinariesPath, "rage"), args...)
	cmd.Stdin = strings.NewReader(data)
	return cmd.Run()
}

func (c *Config) Decrypt(path string) (string, error) {
	args := []string{}
	args = append(args, "--decrypt")
	args = append(args, "--identity", c.Identity)
	args = append(args, path)

	output, err := exec.Command(filepath.Join(c.BinariesPath, "rage"), args...).Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
