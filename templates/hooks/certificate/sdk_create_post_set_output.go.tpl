	// See note on https://docs.aws.amazon.com/acm/latest/APIReference/API_RequestCertificate.html
	// about DescribeCertificate not being ready to call for several seconds
	// after a successful RequestCertificate API call...
	waitAfterSuccessfulCreate()
