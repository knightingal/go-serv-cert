package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	mrand "math/rand"
)

func fetchCert(context *gin.Context) {
	ca, caPEMByte, caPrivKey := loadCa()
	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(mrand.Int63()),
		Subject: pkix.Name{
			Organization:  []string{"Home"},
			CommonName:    "knightingal device",
			Country:       []string{"CN"},
			Province:      []string{"JS"},
			Locality:      []string{"Nanking"},
			StreetAddress: []string{"Ruanjiandadao Street 101"},
			PostalCode:    []string{"210012"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	clientCertPEM, clientCertPrivKeyPEM, _, _ := createAndSign(clientCert, ca, caPrivKey)
	data := gin.H{
		"crt": clientCertPEM.String(),
		"key": clientCertPrivKeyPEM.String(),
		"ca":  caPEMByte.String(),
	}

	context.JSONP(http.StatusOK, data)
}

func main() {
	router := gin.Default()
	router.GET("/go-fetch-cert", fetchCert)

	// get our ca and server certificate
	serverTLSConf, clientTLSConf, err := certsetup()
	if err != nil {
		panic(err)
	}

	s8082 := &http.Server{
		Addr:           ":8082",
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      serverTLSConf,
	}
	go s8082.ListenAndServeTLS("", "")

	handle8081 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "success!")
	})

	s8081 := &http.Server{
		Addr:           ":8081",
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      serverTLSConf,
		Handler:        handle8081,
	}
	go s8081.ListenAndServeTLS("", "")

	// communicate with the server using an http.Client configured to trust our CA
	transport := &http.Transport{
		TLSClientConfig: clientTLSConf,
	}
	http := http.Client{
		Transport: transport,
	}
	resp, err := http.Get("https://nanking-company.com:8081")
	if err != nil {
		panic(err)
	}

	// verify the response
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	body := strings.TrimSpace(string(respBodyBytes[:]))
	fmt.Println(body)
	c := make(chan int)
	<-c

}

func createCA(certificate *x509.Certificate, certPrivKey *rsa.PrivateKey) (
	certPEM *bytes.Buffer,
	keyPEM *bytes.Buffer,
	pCertBytes *[]byte,
	pKeyByte *[]byte,
	caPk *rsa.PrivateKey) {

	if certPrivKey == nil {
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		caPk = certPrivKey

		if err != nil {
			return
		}

	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &caPk.PublicKey, caPk)
	if err != nil {
		return
	}

	certPEM = new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	keyByte := x509.MarshalPKCS1PrivateKey(caPk)

	keyPEM = new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyByte,
	})

	pCertBytes = &certBytes
	pKeyByte = &keyByte

	return
}

func createAndSign(
	certificate *x509.Certificate,
	ca *x509.Certificate,
	caPk *rsa.PrivateKey) (
	certPEM, keyPEM *bytes.Buffer, pCertBytes, pKeyByte *[]byte) {

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certificate, ca, &certPrivKey.PublicKey, caPk)
	if err != nil {
		return
	}

	certPEM = new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	keyByte := x509.MarshalPKCS1PrivateKey(certPrivKey)

	keyPEM = new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyByte,
	})

	pCertBytes = &certBytes
	pKeyByte = &keyByte

	return
}

func loadCa() (ca *x509.Certificate, caPEM *bytes.Buffer, caPrivKey *rsa.PrivateKey) {
	caPEMByte, err1 := os.ReadFile("ca.crt")
	caPKPEMByte, err2 := os.ReadFile("ca.key")
	var caPrivKeyPEM *bytes.Buffer
	if err1 != nil && err2 != nil {
		ca = &x509.Certificate{
			SerialNumber: big.NewInt(2019),
			Subject: pkix.Name{
				Organization:  []string{"CA Nanking, INC."},
				CommonName:    "ca-nanking.org",
				Country:       []string{"CN"},
				Province:      []string{"JS"},
				Locality:      []string{"Nanking"},
				StreetAddress: []string{"Ruanjiandadao Street 101"},
				PostalCode:    []string{"210012"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}

		caPEM, caPrivKeyPEM, _, _, caPrivKey = createCA(ca, nil)
		os.WriteFile("ca.crt", caPEM.Bytes(), 0666)
		os.WriteFile("ca.key", caPrivKeyPEM.Bytes(), 0666)

	} else {
		caPKBlock, _ := pem.Decode(caPKPEMByte)
		caBlock, _ := pem.Decode(caPEMByte)
		caPrivKey, _ = x509.ParsePKCS1PrivateKey(caPKBlock.Bytes)
		caPEM = new(bytes.Buffer)
		caPEM.Write(caPEMByte)
		caPrivKeyPEM = new(bytes.Buffer)
		caPrivKeyPEM.Write(caPKPEMByte)
		ca, _ = x509.ParseCertificate(caBlock.Bytes)
	}
	return
}

func certsetup() (serverTLSConf *tls.Config, clientTLSConf *tls.Config, err error) {
	caPEMByte, err1 := os.ReadFile("ca.crt")
	caPKPEMByte, err2 := os.ReadFile("ca.key")
	cap12, err3 := os.ReadFile("cab.p12")
	var caPEM *bytes.Buffer
	var caPrivKeyPEM *bytes.Buffer
	var caPrivKey *rsa.PrivateKey
	var ca *x509.Certificate
	if err3 == nil {

		pk, cert, _ := pkcs12.Decode(cap12, "000000")
		caPrivKey = pk.(*rsa.PrivateKey)
		ca = cert

		caPEM, _, _, _, _ = createCA(ca, caPrivKey)

	} else if err1 != nil || err2 != nil {
		ca = &x509.Certificate{
			SerialNumber: big.NewInt(2019),
			Subject: pkix.Name{
				Organization:  []string{"CA Nanking, INC."},
				CommonName:    "ca-nanking.org",
				Country:       []string{"CN"},
				Province:      []string{"JS"},
				Locality:      []string{"Nanking"},
				StreetAddress: []string{"Ruanjiandadao Street 101"},
				PostalCode:    []string{"210012"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}

		caPEM, caPrivKeyPEM, _, _, caPrivKey = createCA(ca, nil)
		os.WriteFile("ca.crt", caPEM.Bytes(), 0666)
		os.WriteFile("ca.key", caPrivKeyPEM.Bytes(), 0666)

	} else {
		caPKBlock, _ := pem.Decode(caPKPEMByte)
		caBlock, _ := pem.Decode(caPEMByte)
		caPrivKey, _ = x509.ParsePKCS1PrivateKey(caPKBlock.Bytes)
		caPEM = new(bytes.Buffer)
		caPEM.Write(caPEMByte)
		caPrivKeyPEM = new(bytes.Buffer)
		caPrivKeyPEM.Write(caPKPEMByte)
		ca, err = x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			fmt.Println(err)
		}
	}

	// set up our CA certificate
	mrand.Seed(time.Now().Unix())

	// set up our server certificate
	servCert := &x509.Certificate{
		SerialNumber: big.NewInt(mrand.Int63()),
		Subject: pkix.Name{
			Organization:  []string{"NankingCompany, INC."},
			CommonName:    "nanking-company.com",
			Country:       []string{"CN"},
			Province:      []string{"JS"},
			Locality:      []string{"Nanking"},
			StreetAddress: []string{"Ruanjiandadao Street 101"},
			PostalCode:    []string{"210012"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"nanking-company.com", "nanjing-comany.cn"},
	}

	servCertPEM, servCertPrivKeyPEM, _, _ := createAndSign(servCert, ca, caPrivKey)

	serverCert, err := tls.X509KeyPair(servCertPEM.Bytes(), servCertPrivKeyPEM.Bytes())
	if err != nil {
		return nil, nil, err
	}

	os.WriteFile("servCert.crt", servCertPEM.Bytes(), 0666)
	os.WriteFile("servCert.key", servCertPrivKeyPEM.Bytes(), 0666)

	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(mrand.Int63()),
		Subject: pkix.Name{
			Organization:  []string{"Home"},
			CommonName:    "knightingal device",
			Country:       []string{"CN"},
			Province:      []string{"JS"},
			Locality:      []string{"Nanking"},
			StreetAddress: []string{"Ruanjiandadao Street 101"},
			PostalCode:    []string{"210012"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"nanking-company.com", "nanjing-comany.cn"},
	}
	clientCertPEM, clientCertPrivKeyPEM, _, _ := createAndSign(clientCert, ca, caPrivKey)
	os.WriteFile("clientCert.crt", clientCertPEM.Bytes(), 0666)
	os.WriteFile("clientCert.key", clientCertPrivKeyPEM.Bytes(), 0666)

	clientPKBlock, _ := pem.Decode(clientCertPrivKeyPEM.Bytes())
	clientCertBlock, _ := pem.Decode(clientCertPEM.Bytes())

	clientPrivKey, _ := x509.ParsePKCS1PrivateKey(clientPKBlock.Bytes)

	clientCert, _ = x509.ParseCertificate(clientCertBlock.Bytes)

	clientP12Data, _ := pkcs12.Encode(rand.Reader, clientPrivKey, clientCert, []*x509.Certificate{ca}, "000000")
	os.WriteFile("client.p12", clientP12Data, 0666)

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certpool,
	}

	clientCertPair, err := tls.X509KeyPair(clientCertPEM.Bytes(), clientCertPrivKeyPEM.Bytes())
	clientTLSConf = &tls.Config{
		Certificates: []tls.Certificate{clientCertPair},
		RootCAs:      certpool,
	}

	return
}
