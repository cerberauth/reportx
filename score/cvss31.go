package score

import (
	"fmt"
	"math"
	"strings"
)

var (
	avWeights  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acWeights  = map[string]float64{"L": 0.77, "H": 0.44}
	prWeightsU = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWeightsC = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	uiWeights  = map[string]float64{"N": 0.85, "R": 0.62}
	ciaWeights = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.00}
)

func roundup31(x float64) float64 {
	return math.Ceil(x*10) / 10
}

func CalculateV31(vector string) (float64, error) {
	if !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, fmt.Errorf("cvss31: invalid prefix in %q", vector)
	}
	parts := strings.Split(vector[len("CVSS:3.1/"):], "/")
	metrics := make(map[string]string, len(parts))
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			return 0, fmt.Errorf("cvss31: malformed metric %q", p)
		}
		metrics[kv[0]] = kv[1]
	}

	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, k := range required {
		if _, ok := metrics[k]; !ok {
			return 0, fmt.Errorf("cvss31: missing metric %q", k)
		}
	}

	scope := metrics["S"]
	if scope != "U" && scope != "C" {
		return 0, fmt.Errorf("cvss31: invalid S value %q", scope)
	}

	av, ok := avWeights[metrics["AV"]]
	if !ok {
		return 0, fmt.Errorf("cvss31: invalid AV value %q", metrics["AV"])
	}
	ac, ok := acWeights[metrics["AC"]]
	if !ok {
		return 0, fmt.Errorf("cvss31: invalid AC value %q", metrics["AC"])
	}

	var pr float64
	if scope == "C" {
		pr, ok = prWeightsC[metrics["PR"]]
	} else {
		pr, ok = prWeightsU[metrics["PR"]]
	}
	if !ok {
		return 0, fmt.Errorf("cvss31: invalid PR value %q", metrics["PR"])
	}

	ui, ok := uiWeights[metrics["UI"]]
	if !ok {
		return 0, fmt.Errorf("cvss31: invalid UI value %q", metrics["UI"])
	}
	c, ok := ciaWeights[metrics["C"]]
	if !ok {
		return 0, fmt.Errorf("cvss31: invalid C value %q", metrics["C"])
	}
	i, ok := ciaWeights[metrics["I"]]
	if !ok {
		return 0, fmt.Errorf("cvss31: invalid I value %q", metrics["I"])
	}
	a, ok := ciaWeights[metrics["A"]]
	if !ok {
		return 0, fmt.Errorf("cvss31: invalid A value %q", metrics["A"])
	}

	iscBase := 1 - (1-c)*(1-i)*(1-a)

	var isc float64
	if scope == "U" {
		isc = 6.42 * iscBase
	} else {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	}

	if isc <= 0 {
		return 0.0, nil
	}

	exploitability := 8.22 * av * ac * pr * ui

	var baseScore float64
	if scope == "U" {
		baseScore = roundup31(math.Min(isc+exploitability, 10))
	} else {
		baseScore = roundup31(math.Min(1.08*(isc+exploitability), 10))
	}

	return baseScore, nil
}
