package config

import (
	"Dory/internal/party"
	"encoding/base64"
	"io/ioutil"
	"strconv"

	"github.com/pkg/errors"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"gopkg.in/yaml.v2"
)

var ConfigReadError = errors.New("config read fail, check config.yaml in root directory")
var NotReadFileError = errors.New("execute run ReadConfig function before querying config")
var NotDefined = errors.New("this item in config is allowed to omit")

// Implement Config interface in local linux machine setting
type Config struct {
	N int `yaml:"N"`
	F int `yaml:"F"`

	IPList   []string `yaml:"IPList"`
	PortList []string `yaml:"PortList"`
	Txnum    int      `yaml:"Txnum"`
	// judge if execute read config function before
	// default is false in golang structure declare
	isRead    bool
	PID       int      `yaml:"PID"`
	Statistic string   `yaml:"Statistic"`
	TSSconfig []string `yaml:"TSSconfig"`
	//TSEconfig []string `yaml:"TSEconfig"`
	// server start time
	PrepareTime int `yaml:"PrepareTime"`
	WaitTime    int `yaml:"WaitTime"`

	TestEpochs int `yaml:"TestEpochs"`
}

func NewConfig(configName string, isLocal bool) (Config, error) {
	c := Config{}
	err := c.ReadConfig(configName, isLocal)
	if err != nil {
		return Config{}, err
	}
	return c, err
}

// read config from ConfigName file location
func (c *Config) ReadConfig(ConfigName string, isLocal bool) error {
	byt, err := ioutil.ReadFile(ConfigName)
	if err != nil {
		goto ret
	}

	err = yaml.Unmarshal(byt, c)

	c.isRead = true

	if !isLocal {
		if err != nil {
			goto ret
		}

		if c.N <= 0 || c.F < 0 {
			return errors.Wrap(errors.New("N or F is negative"),
				ConfigReadError.Error())
		}

		if c.N != len(c.IPList) || c.N != len(c.PortList) {
			return errors.Wrap(errors.New("ip list"+
				" length or port list length isn't match N"),
				ConfigReadError.Error())
		}
		// id is begin from 0 to ... N-1
		if c.PID >= c.N || c.PID < 0 {
			return errors.New("ID is begin from 0 to N-1")
		}
	}

	return nil
ret:
	return errors.Wrap(err, ConfigReadError.Error())
}

// Achieve numbers of total nodes
// the return value is a positive integer
func (c *Config) GetN() (int, error) {
	if !c.isRead {
		return 0, NotReadFileError
	}
	return c.N, nil
}

// Achieve number of corrupted nodes
// return value is a positive integer
func (c *Config) GetF() (int, error) {
	if !c.isRead {
		return 0, NotReadFileError
	}
	return c.F, nil
}

// Achieve ip list if defined
// return a ip list of defined ip in config file
func (c *Config) GetIPList() ([]string, error) {
	if !c.isRead {
		return nil, NotReadFileError
	}
	if len(c.IPList) == 0 {
		return nil, NotDefined
	}
	return c.IPList, nil
}

// Achieve port list if defined
// return a port list of defined port in config file
func (c *Config) GetPortList() ([]string, error) {
	if !c.isRead {
		return nil, NotReadFileError
	}
	if len(c.PortList) == 0 {
		return nil, NotDefined
	}
	return c.PortList, nil
}

func (c *Config) GetMyID() (int, error) {
	if !c.isRead {
		return 0, NotReadFileError
	}
	return c.PID, nil
}

func (c *Config) Marshal(location string) error {
	byts, err := yaml.Marshal(c)
	if err != nil {
		return errors.Wrap(err, "marshal config fail")
	}
	err = ioutil.WriteFile(location, byts, 0777)
	if err != nil {
		return errors.Wrap(err, "marshal config fail")
	}
	return nil
}

type TSSconfig struct {
	N  int
	T  int
	Sk *share.PriShare
	Pk *share.PubPoly
}

func (c *TSSconfig) Marshal() ([]string, error) {
	result := make([]string, 6)
	result[0] = strconv.Itoa(c.T)
	result[1] = strconv.Itoa(c.N)
	result[2] = strconv.Itoa(c.Sk.I)
	// marshal psk
	byts, err := c.Sk.V.MarshalBinary()
	if err != nil {
		return nil, errors.Wrapf(err, "fail to marshal TSSconfig.sk.V")
	}
	result[3] = base64.StdEncoding.EncodeToString(byts)

	base, committs := c.Pk.Info()
	// marshal base
	byts, err = base.MarshalBinary()
	if err != nil {
		return nil, errors.Wrapf(err, "fail to marshal TSSconfig.pk.base")
	}
	result[4] = base64.StdEncoding.EncodeToString(byts)
	// marshal committs
	result[5] = strconv.Itoa(len(committs))
	for i, commit := range committs {
		byts, err = commit.MarshalBinary()
		if err != nil {
			return nil, errors.Wrapf(err, "fail to marshal TSSconfig.pk.commit[%d]", i)
		}
		result = append(result, base64.StdEncoding.EncodeToString(byts))
	}
	return result, nil
}

func (c *TSSconfig) UnMarshal(s []string) error {
	suit := pairing.NewSuiteBn256()
	var err error
	c.T, err = strconv.Atoi(s[0])
	if err != nil {
		return errors.Wrap(err, "fail to unmarshal T")
	}
	c.N, err = strconv.Atoi(s[1])
	if err != nil {
		return errors.Wrap(err, "fail to unmarshal N")
	}
	// unmarshal psk
	i, err := strconv.Atoi(s[2])
	if err != nil {
		return errors.Wrap(err, "fail to unmarshal psk.i")
	}
	vbytes, err := base64.StdEncoding.DecodeString(s[3])
	if err != nil {
		return errors.Wrap(err, "fail to unmarshal psk.v")
	}
	v := suit.G1().Scalar()
	err = v.UnmarshalBinary(vbytes)
	if err != nil {
		return errors.Wrap(err, "fail to unmarshal psk.v")
	}
	c.Sk = &share.PriShare{
		I: i,
		V: v,
	}
	// ummarshal pk
	baseByts, err := base64.StdEncoding.DecodeString(s[4])
	if err != nil {
		return errors.Wrap(err, "fail to unmarshal pk.base")
	}
	base := suit.G2().Point()
	err = base.UnmarshalBinary(baseByts)
	if err != nil {
		return errors.Wrap(err, "fail to unmarshal pk.base")
	}
	committsLen, err := strconv.Atoi(s[5])
	if err != nil {
		return errors.Wrap(err, "fail to unmarshal pk.committsLen")
	}
	if committsLen+6 != len(s) {
		return errors.Errorf("pk.committsLen = %d; len(s) = %d", committsLen, len(s))
	}
	committs := make([]kyber.Point, committsLen)
	for i := 0; i < committsLen; i++ {
		commit := suit.G2().Point()
		commitByts, err := base64.StdEncoding.DecodeString(s[6+i])
		if err != nil {
			return errors.Wrapf(err, "fail to unmarshal pk.committs[%d]", i)
		}
		err = commit.UnmarshalBinary(commitByts)
		if err != nil {
			return errors.Wrapf(err, "fail to unmarshal pk.committs[%d]", i)
		}
		committs[i] = commit
	}
	c.Pk = share.NewPubPoly(suit.G2(), base, committs)
	return nil
}

func (c *Config) RemoteGen(dir string) error {
	//TSS config
	sks, pk := party.SigKeyGen(uint32(c.N), uint32(2*c.F+1))
	tssConfigs := []*TSSconfig{}
	for _, sk := range sks {
		tssConfigs = append(tssConfigs, &TSSconfig{
			N:  c.N,
			T:  2*c.F + 1,
			Pk: pk,
			Sk: sk,
		})
	}

	for i := 0; i < c.N; i++ {
		c.PID = i
		tssM, err := tssConfigs[i].Marshal()
		if err != nil {
			return errors.Wrap(err, "generate cc_config fail")
		}
		c.TSSconfig = tssM
		// tseM, err := tseConfigs[i].Marshal()
		if err != nil {
			return errors.Wrap(err, "generate e_config fail")
		}
		//c.TSEconfig = tseM
		err = c.Marshal(dir + "/config_" + strconv.Itoa(i) + ".yaml")
		if err != nil {
			return errors.Wrap(err, "marshal config fail")
		}
	}
	return nil
}
