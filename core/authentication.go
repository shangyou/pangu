package core

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	//"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"pangu/config"
	"pangu/utils"
	"regexp"
	"strings"
	"time"
)

var jar = new(Jar)
var cookieStr = ""

func weiboLoginPre1() map[string]interface{} {

	client := &http.Client{}

	reqest, err := http.NewRequest("GET", config.LOGIN_FIRST_URL, nil)

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	reqest.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	reqest.Header.Add("Accept-Encoding", "gzip, deflate")
	reqest.Header.Add("Accept-Language", "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3")
	reqest.Header.Add("Connection", "keep-alive")
	reqest.Header.Add("Host", "login.sina.com.cn")
	reqest.Header.Add("Referer", "http://weibo.com/")
	reqest.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0")
	response, err := client.Do(reqest)
	defer response.Body.Close()

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	if response.StatusCode == 200 {

		var body string

		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ := gzip.NewReader(response.Body)
			body = utils.ReadAll(reader)
		default:
			bodyByte, _ := ioutil.ReadAll(response.Body)
			body = string(bodyByte)
		}

		r := regexp.MustCompile(`sinaSSOController.preloginCallBack\((.*?)\)`)
		rs := r.FindStringSubmatch(body)

		//json decode
		header := make(map[string]interface{})
		err = json.Unmarshal([]byte(rs[1]), &header)
		if err != nil {
			fmt.Println("Fatal error ", err.Error())
			os.Exit(0)
		}

		t := fmt.Sprintf("%f", header["servertime"])

		header["servertime"] = strings.Trim(t, ".000000")

		return header
	}

	return nil
}

func weiboLoginPre2(header map[string]interface{}) string {

	currentTime := time.Now().Unix() + int64(rand.Float32()*999)

	v := url.Values{}
	v.Set("entry", "weibo")
	v.Add("gateway", "1")
	v.Add("from", "")
	v.Add("savestate", "7")
	v.Add("useticket", "1")
	v.Add("service", "miniblog")
	v.Add("servertime", utils.Change(header["servertime"]))
	v.Add("rsakv", utils.Change(header["rsakv"]))
	v.Add("pcid", utils.Change(header["pcid"]))
	v.Add("nonce", utils.Change(header["nonce"]))
	v.Add("pwencode", "rsa2")
	v.Add("returntype", "META")
	v.Add("encoding", "UTF-8")
	v.Add("vsnf", "1")
	v.Add("pagerefer", "")
	v.Add("url", "http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack")
	v.Add("su", base64.StdEncoding.EncodeToString([]byte(config.LOGIN_USERNAME)))

	password := sinaRSA2SSOEncoder(utils.Change(header["pubkey"]), config.LOGIN_PASSWORD, utils.Change(header["servertime"]), utils.Change(header["nonce"]))
	v.Add("sp", password)

	currentTime1 := time.Now().Unix() + int64(rand.Float32()*999)

	prelt := fmt.Sprintf("%f", math.Max(float64(currentTime1-currentTime), 100.0))

	prelt = strings.Trim(prelt, ".000000")

	v.Add("prelt", prelt)

	client := &http.Client{nil, nil, jar}

	reqest, err := http.NewRequest("POST", "http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.5)", strings.NewReader(v.Encode()))

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	reqest.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	reqest.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	reqest.Header.Add("Accept-Encoding", "gzip, deflate")
	reqest.Header.Add("Accept-Language", "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3")
	reqest.Header.Add("Connection", "keep-alive")
	reqest.Header.Add("Host", "login.sina.com.cn")
	reqest.Header.Add("Referer", "http://weibo.com/")
	reqest.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0")
	response, err := client.Do(reqest)
	defer response.Body.Close()

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	if response.StatusCode == 200 {

		var body string

		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ := gzip.NewReader(response.Body)
			body = utils.ReadAll(reader)
		default:
			bodyByte, _ := ioutil.ReadAll(response.Body)
			body = string(bodyByte)
		}

		r := regexp.MustCompile(`location.replace\("(.*?)"\)`)
		rs := r.FindStringSubmatch(body)

		if strings.Contains(rs[1], "retcode=0") {
			parseHeaderParamter(response.Header)

			return rs[1]
		}
	}

	return ""
}

func weiboLoginPre3(userInfoUrl string) string {
	client := &http.Client{nil, nil, jar}

	reqest, err := http.NewRequest("GET", userInfoUrl, nil)

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	reqest.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	reqest.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	reqest.Header.Add("Accept-Encoding", "gzip,deflate,sdch")
	reqest.Header.Add("Accept-Language", "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3")
	reqest.Header.Add("Connection", "keep-alive")
	reqest.Header.Add("Host", "weibo.com")
	reqest.Header.Add("Referer", "http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.5)")
	reqest.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36")
	response, err := client.Do(reqest)
	defer response.Body.Close()

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	if response.StatusCode == 200 {

		var body string

		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ := gzip.NewReader(response.Body)
			body = utils.ReadAll(reader)
		default:
			bodyByte, _ := ioutil.ReadAll(response.Body)
			body = string(bodyByte)
		}

		r := regexp.MustCompile(`"uniqueid":"(.*?)"`)
		rs := r.FindStringSubmatch(string(body))

		parseHeaderParamter(response.Header)

		return rs[1]
	}

	return ""
}

func weiboLoginPre4(weiboUid string) {
	client := &http.Client{nil, nil, jar}

	reqest, err := http.NewRequest("GET", "http://weibo.com/u/"+weiboUid+"?wvr=5&lf=reg", nil)

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	reqest.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	reqest.Header.Add("Cookie", cookieStr)
	reqest.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	reqest.Header.Add("Accept-Encoding", "gzip,deflate,sdch")
	reqest.Header.Add("Accept-Language", "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3")
	reqest.Header.Add("Connection", "keep-alive")
	reqest.Header.Add("Host", "weibo.com")
	reqest.Header.Add("Referer", "http://weibo.com/")
	reqest.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36")
	response, err := client.Do(reqest)
	defer response.Body.Close()

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	if response.StatusCode == 200 {

		parseHeaderParamter(response.Header)
	}
}

func getWeibo(weiboUid string) {
	client := &http.Client{nil, nil, jar}

	reqest, err := http.NewRequest("GET", "http://weibo.com/p/1005052216172320/weibo?from=page_100505&mod=TAB#place", nil)

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	reqest.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	reqest.Header.Add("Cookie", cookieStr)
	reqest.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	reqest.Header.Add("Accept-Encoding", "gzip,deflate,sdch")
	reqest.Header.Add("Accept-Language", "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3")
	reqest.Header.Add("Connection", "keep-alive")
	reqest.Header.Add("Host", "weibo.com")
	reqest.Header.Add("Referer", "http://weibo.com/")
	reqest.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36")
	response, err := client.Do(reqest)
	defer response.Body.Close()

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(0)
	}

	if response.StatusCode == 200 {

		var body string

		fmt.Println(response.Header.Get("Content-lenght"))

		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, _ := gzip.NewReader(response.Body)
			body = utils.ReadAll(reader)
		default:
			bodyByte, _ := ioutil.ReadAll(response.Body)
			body = string(bodyByte)
		}

		outputFile, _ := os.Create(config.LOG_PATH + weiboUid + ".log")
		defer outputFile.Close()
		outputFile.WriteString(body)
	}
}

func parseHeaderParamter(header http.Header) {
	if header["Set-Cookie"] != nil {
		for _, value := range header["Set-Cookie"] {
			if strings.Index(value, "SUS=") == 0 {
				cookieStr += string([]byte(value)[0 : strings.Index(value, ";")+1])
			} else if strings.Index(value, "SUE=") == 0 {
				cookieStr += string([]byte(value)[0 : strings.Index(value, ";")+1])
			} else if strings.Index(value, "SUP=") == 0 {
				cookieStr += string([]byte(value)[0 : strings.Index(value, ";")+1])
			} else if strings.Index(value, "USRHAWB=") == 0 {
				cookieStr += string([]byte(value)[0 : strings.Index(value, ";")+1])
			}
		}
	}
}

func sinaRSA2SSOEncoder(pubKey string, pwd string, servertime string, nonce string) string {
	out, err := exec.Command(config.GET_PWD_SHELL, pubKey, servertime, nonce, pwd).Output()
	if err != nil {
		fmt.Println(err.Error())
	}

	return string(out)
}

func Start() {
	header := weiboLoginPre1()
	userInfoUrl := weiboLoginPre2(header)
	weiboUid := weiboLoginPre3(userInfoUrl)
	weiboLoginPre4(weiboUid)
	getWeibo(weiboUid)
}
