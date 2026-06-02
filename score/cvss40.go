package score

import (
	"fmt"
	"math"
	"strings"
)

var (
	av40  = map[string]int{"N": 0, "A": 1, "L": 2, "P": 3}
	ac40  = map[string]int{"L": 0, "H": 1}
	at40  = map[string]int{"N": 0, "P": 1}
	pr40  = map[string]int{"N": 0, "L": 1, "H": 2}
	ui40  = map[string]int{"N": 0, "P": 1, "A": 2}
	cia40 = map[string]int{"H": 0, "L": 1, "N": 2}
	e40   = map[string]int{"A": 0, "P": 1, "U": 2}
)

var cvss40MeanScores = map[[5]int]float64{
	{0, 0, 0, 0, 0}: 10.0, {0, 0, 0, 0, 1}: 9.9, {0, 0, 0, 0, 2}: 9.8,
	{0, 0, 0, 1, 0}: 10.0, {0, 0, 0, 1, 1}: 9.9, {0, 0, 0, 1, 2}: 9.5,
	{0, 0, 0, 2, 0}: 9.3, {0, 0, 0, 2, 1}: 8.7, {0, 0, 0, 2, 2}: 8.1,
	{0, 0, 1, 0, 0}: 9.5, {0, 0, 1, 0, 1}: 9.1, {0, 0, 1, 0, 2}: 8.3,
	{0, 0, 1, 1, 0}: 9.5, {0, 0, 1, 1, 1}: 9.1, {0, 0, 1, 1, 2}: 8.3,
	{0, 0, 1, 2, 0}: 8.4, {0, 0, 1, 2, 1}: 7.4, {0, 0, 1, 2, 2}: 6.4,
	{0, 0, 2, 0, 0}: 9.0, {0, 0, 2, 0, 1}: 8.4, {0, 0, 2, 0, 2}: 7.8,
	{0, 0, 2, 1, 0}: 9.0, {0, 0, 2, 1, 1}: 8.4, {0, 0, 2, 1, 2}: 7.8,
	{0, 0, 2, 2, 0}: 8.0, {0, 0, 2, 2, 1}: 7.3, {0, 0, 2, 2, 2}: 6.7,
	{0, 0, 3, 0, 0}: 9.0, {0, 0, 3, 0, 1}: 8.7, {0, 0, 3, 0, 2}: 7.8,
	{0, 0, 3, 1, 0}: 9.0, {0, 0, 3, 1, 1}: 8.7, {0, 0, 3, 1, 2}: 7.8,
	{0, 0, 3, 2, 0}: 8.3, {0, 0, 3, 2, 1}: 7.6, {0, 0, 3, 2, 2}: 6.9,
	{0, 0, 4, 0, 0}: 9.0, {0, 0, 4, 0, 1}: 8.5, {0, 0, 4, 0, 2}: 7.8,
	{0, 0, 4, 1, 0}: 8.7, {0, 0, 4, 1, 1}: 7.5, {0, 0, 4, 1, 2}: 6.2,
	{0, 0, 4, 2, 0}: 6.9, {0, 0, 4, 2, 1}: 5.5, {0, 0, 4, 2, 2}: 4.2,
	{0, 1, 0, 0, 0}: 9.5, {0, 1, 0, 0, 1}: 9.3, {0, 1, 0, 0, 2}: 9.0,
	{0, 1, 0, 1, 0}: 9.2, {0, 1, 0, 1, 1}: 8.9, {0, 1, 0, 1, 2}: 8.6,
	{0, 1, 0, 2, 0}: 8.0, {0, 1, 0, 2, 1}: 7.5, {0, 1, 0, 2, 2}: 6.5,
	{0, 1, 1, 0, 0}: 9.0, {0, 1, 1, 0, 1}: 8.7, {0, 1, 1, 0, 2}: 7.7,
	{0, 1, 1, 1, 0}: 9.0, {0, 1, 1, 1, 1}: 8.7, {0, 1, 1, 1, 2}: 7.7,
	{0, 1, 1, 2, 0}: 7.5, {0, 1, 1, 2, 1}: 6.6, {0, 1, 1, 2, 2}: 5.8,
	{0, 1, 2, 0, 0}: 8.5, {0, 1, 2, 0, 1}: 7.7, {0, 1, 2, 0, 2}: 7.0,
	{0, 1, 2, 1, 0}: 8.5, {0, 1, 2, 1, 1}: 7.7, {0, 1, 2, 1, 2}: 7.0,
	{0, 1, 2, 2, 0}: 7.4, {0, 1, 2, 2, 1}: 6.6, {0, 1, 2, 2, 2}: 5.8,
	{0, 1, 3, 0, 0}: 8.5, {0, 1, 3, 0, 1}: 8.2, {0, 1, 3, 0, 2}: 7.1,
	{0, 1, 3, 1, 0}: 8.5, {0, 1, 3, 1, 1}: 8.2, {0, 1, 3, 1, 2}: 7.1,
	{0, 1, 3, 2, 0}: 7.4, {0, 1, 3, 2, 1}: 6.8, {0, 1, 3, 2, 2}: 5.9,
	{0, 1, 4, 0, 0}: 8.0, {0, 1, 4, 0, 1}: 7.4, {0, 1, 4, 0, 2}: 6.7,
	{0, 1, 4, 1, 0}: 7.8, {0, 1, 4, 1, 1}: 6.5, {0, 1, 4, 1, 2}: 5.2,
	{0, 1, 4, 2, 0}: 6.0, {0, 1, 4, 2, 1}: 5.0, {0, 1, 4, 2, 2}: 3.9,
	{1, 0, 0, 0, 0}: 9.3, {1, 0, 0, 0, 1}: 8.9, {1, 0, 0, 0, 2}: 8.8,
	{1, 0, 0, 1, 0}: 9.3, {1, 0, 0, 1, 1}: 8.9, {1, 0, 0, 1, 2}: 8.8,
	{1, 0, 0, 2, 0}: 8.5, {1, 0, 0, 2, 1}: 7.4, {1, 0, 0, 2, 2}: 6.9,
	{1, 0, 1, 0, 0}: 8.0, {1, 0, 1, 0, 1}: 7.6, {1, 0, 1, 0, 2}: 7.0,
	{1, 0, 1, 1, 0}: 8.9, {1, 0, 1, 1, 1}: 8.0, {1, 0, 1, 1, 2}: 7.0,
	{1, 0, 1, 2, 0}: 7.5, {1, 0, 1, 2, 1}: 6.7, {1, 0, 1, 2, 2}: 5.9,
	{1, 0, 2, 0, 0}: 7.5, {1, 0, 2, 0, 1}: 6.9, {1, 0, 2, 0, 2}: 6.2,
	{1, 0, 2, 1, 0}: 7.5, {1, 0, 2, 1, 1}: 6.9, {1, 0, 2, 1, 2}: 6.2,
	{1, 0, 2, 2, 0}: 6.2, {1, 0, 2, 2, 1}: 5.6, {1, 0, 2, 2, 2}: 4.9,
	{1, 0, 3, 0, 0}: 7.8, {1, 0, 3, 0, 1}: 7.2, {1, 0, 3, 0, 2}: 6.4,
	{1, 0, 3, 1, 0}: 7.8, {1, 0, 3, 1, 1}: 7.2, {1, 0, 3, 1, 2}: 6.4,
	{1, 0, 3, 2, 0}: 6.5, {1, 0, 3, 2, 1}: 5.9, {1, 0, 3, 2, 2}: 5.1,
	{1, 0, 4, 0, 0}: 7.0, {1, 0, 4, 0, 1}: 6.5, {1, 0, 4, 0, 2}: 5.8,
	{1, 0, 4, 1, 0}: 7.0, {1, 0, 4, 1, 1}: 6.5, {1, 0, 4, 1, 2}: 5.8,
	{1, 0, 4, 2, 0}: 5.0, {1, 0, 4, 2, 1}: 4.4, {1, 0, 4, 2, 2}: 3.9,
	{1, 1, 0, 0, 0}: 8.5, {1, 1, 0, 0, 1}: 8.0, {1, 1, 0, 0, 2}: 7.5,
	{1, 1, 0, 1, 0}: 8.5, {1, 1, 0, 1, 1}: 8.0, {1, 1, 0, 1, 2}: 7.5,
	{1, 1, 0, 2, 0}: 7.4, {1, 1, 0, 2, 1}: 6.8, {1, 1, 0, 2, 2}: 6.1,
	{1, 1, 1, 0, 0}: 7.6, {1, 1, 1, 0, 1}: 6.8, {1, 1, 1, 0, 2}: 6.0,
	{1, 1, 1, 1, 0}: 7.6, {1, 1, 1, 1, 1}: 6.8, {1, 1, 1, 1, 2}: 6.0,
	{1, 1, 1, 2, 0}: 6.6, {1, 1, 1, 2, 1}: 5.9, {1, 1, 1, 2, 2}: 5.1,
	{1, 1, 2, 0, 0}: 6.8, {1, 1, 2, 0, 1}: 6.2, {1, 1, 2, 0, 2}: 5.5,
	{1, 1, 2, 1, 0}: 6.8, {1, 1, 2, 1, 1}: 6.2, {1, 1, 2, 1, 2}: 5.5,
	{1, 1, 2, 2, 0}: 5.6, {1, 1, 2, 2, 1}: 5.0, {1, 1, 2, 2, 2}: 4.4,
	{1, 1, 3, 0, 0}: 7.0, {1, 1, 3, 0, 1}: 6.4, {1, 1, 3, 0, 2}: 5.6,
	{1, 1, 3, 1, 0}: 7.0, {1, 1, 3, 1, 1}: 6.4, {1, 1, 3, 1, 2}: 5.6,
	{1, 1, 3, 2, 0}: 5.9, {1, 1, 3, 2, 1}: 5.3, {1, 1, 3, 2, 2}: 4.6,
	{1, 1, 4, 0, 0}: 6.0, {1, 1, 4, 0, 1}: 5.4, {1, 1, 4, 0, 2}: 4.8,
	{1, 1, 4, 1, 0}: 6.0, {1, 1, 4, 1, 1}: 5.4, {1, 1, 4, 1, 2}: 4.8,
	{1, 1, 4, 2, 0}: 4.4, {1, 1, 4, 2, 1}: 3.9, {1, 1, 4, 2, 2}: 3.5,
	{2, 0, 0, 0, 0}: 9.0, {2, 0, 0, 0, 1}: 8.5, {2, 0, 0, 0, 2}: 8.0,
	{2, 0, 0, 1, 0}: 8.6, {2, 0, 0, 1, 1}: 8.0, {2, 0, 0, 1, 2}: 7.5,
	{2, 0, 0, 2, 0}: 7.0, {2, 0, 0, 2, 1}: 6.3, {2, 0, 0, 2, 2}: 5.6,
	{2, 0, 1, 0, 0}: 7.5, {2, 0, 1, 0, 1}: 7.3, {2, 0, 1, 0, 2}: 7.0,
	{2, 0, 1, 1, 0}: 7.5, {2, 0, 1, 1, 1}: 7.3, {2, 0, 1, 1, 2}: 7.0,
	{2, 0, 1, 2, 0}: 6.5, {2, 0, 1, 2, 1}: 5.8, {2, 0, 1, 2, 2}: 5.1,
	{2, 0, 2, 0, 0}: 7.0, {2, 0, 2, 0, 1}: 6.5, {2, 0, 2, 0, 2}: 5.9,
	{2, 0, 2, 1, 0}: 7.0, {2, 0, 2, 1, 1}: 6.5, {2, 0, 2, 1, 2}: 5.9,
	{2, 0, 2, 2, 0}: 5.5, {2, 0, 2, 2, 1}: 5.0, {2, 0, 2, 2, 2}: 4.3,
	{2, 0, 3, 0, 0}: 7.5, {2, 0, 3, 0, 1}: 7.2, {2, 0, 3, 0, 2}: 6.5,
	{2, 0, 3, 1, 0}: 7.5, {2, 0, 3, 1, 1}: 7.2, {2, 0, 3, 1, 2}: 6.5,
	{2, 0, 3, 2, 0}: 6.0, {2, 0, 3, 2, 1}: 5.5, {2, 0, 3, 2, 2}: 4.8,
	{2, 0, 4, 0, 0}: 6.5, {2, 0, 4, 0, 1}: 6.2, {2, 0, 4, 0, 2}: 5.5,
	{2, 0, 4, 1, 0}: 6.5, {2, 0, 4, 1, 1}: 6.2, {2, 0, 4, 1, 2}: 5.5,
	{2, 0, 4, 2, 0}: 4.8, {2, 0, 4, 2, 1}: 4.2, {2, 0, 4, 2, 2}: 3.6,
	{2, 1, 0, 0, 0}: 8.0, {2, 1, 0, 0, 1}: 7.5, {2, 1, 0, 0, 2}: 7.0,
	{2, 1, 0, 1, 0}: 7.5, {2, 1, 0, 1, 1}: 7.0, {2, 1, 0, 1, 2}: 6.5,
	{2, 1, 0, 2, 0}: 6.0, {2, 1, 0, 2, 1}: 5.5, {2, 1, 0, 2, 2}: 4.9,
	{2, 1, 1, 0, 0}: 7.0, {2, 1, 1, 0, 1}: 6.5, {2, 1, 1, 0, 2}: 6.0,
	{2, 1, 1, 1, 0}: 7.0, {2, 1, 1, 1, 1}: 6.5, {2, 1, 1, 1, 2}: 6.0,
	{2, 1, 1, 2, 0}: 5.5, {2, 1, 1, 2, 1}: 4.9, {2, 1, 1, 2, 2}: 4.3,
	{2, 1, 2, 0, 0}: 6.5, {2, 1, 2, 0, 1}: 6.0, {2, 1, 2, 0, 2}: 5.5,
	{2, 1, 2, 1, 0}: 6.5, {2, 1, 2, 1, 1}: 6.0, {2, 1, 2, 1, 2}: 5.5,
	{2, 1, 2, 2, 0}: 5.0, {2, 1, 2, 2, 1}: 4.5, {2, 1, 2, 2, 2}: 3.9,
	{2, 1, 3, 0, 0}: 7.0, {2, 1, 3, 0, 1}: 6.5, {2, 1, 3, 0, 2}: 5.8,
	{2, 1, 3, 1, 0}: 7.0, {2, 1, 3, 1, 1}: 6.5, {2, 1, 3, 1, 2}: 5.8,
	{2, 1, 3, 2, 0}: 5.5, {2, 1, 3, 2, 1}: 4.9, {2, 1, 3, 2, 2}: 4.2,
	{2, 1, 4, 0, 0}: 5.5, {2, 1, 4, 0, 1}: 5.2, {2, 1, 4, 0, 2}: 4.5,
	{2, 1, 4, 1, 0}: 5.5, {2, 1, 4, 1, 1}: 5.2, {2, 1, 4, 1, 2}: 4.5,
	{2, 1, 4, 2, 0}: 4.0, {2, 1, 4, 2, 1}: 3.5, {2, 1, 4, 2, 2}: 2.9,
}

func lookupMeanScore(eq1, eq2, eq3eq6, eq4, eq5 int) (float64, bool) {
	if eq1 < 0 || eq2 < 0 || eq3eq6 < 0 || eq4 < 0 || eq5 < 0 {
		return 0, false
	}
	score, ok := cvss40MeanScores[[5]int{eq1, eq2, eq3eq6, eq4, eq5}]
	return score, ok
}

func CalculateV40(vector string) (float64, error) {
	if !strings.HasPrefix(vector, "CVSS:4.0/") {
		return 0, fmt.Errorf("cvss40: invalid prefix in %q", vector)
	}
	parts := strings.Split(vector[len("CVSS:4.0/"):], "/")
	m := make(map[string]string, len(parts))
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			return 0, fmt.Errorf("cvss40: malformed metric %q", p)
		}
		m[kv[0]] = kv[1]
	}

	required := []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return 0, fmt.Errorf("cvss40: missing required metric %q", k)
		}
	}

	if _, ok := av40[m["AV"]]; !ok {
		return 0, fmt.Errorf("cvss40: invalid AV %q", m["AV"])
	}
	if _, ok := ac40[m["AC"]]; !ok {
		return 0, fmt.Errorf("cvss40: invalid AC %q", m["AC"])
	}
	if _, ok := at40[m["AT"]]; !ok {
		return 0, fmt.Errorf("cvss40: invalid AT %q", m["AT"])
	}
	if _, ok := pr40[m["PR"]]; !ok {
		return 0, fmt.Errorf("cvss40: invalid PR %q", m["PR"])
	}
	if _, ok := ui40[m["UI"]]; !ok {
		return 0, fmt.Errorf("cvss40: invalid UI %q", m["UI"])
	}
	for _, k := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if _, ok := cia40[m[k]]; !ok {
			return 0, fmt.Errorf("cvss40: invalid %s %q", k, m[k])
		}
	}

	eVal := "A"
	if v, ok := m["E"]; ok {
		if _, ok2 := e40[v]; !ok2 {
			return 0, fmt.Errorf("cvss40: invalid E %q", v)
		}
		eVal = v
	}

	eq1 := computeEQ1(m["AV"], m["PR"], m["UI"])
	eq2 := computeEQ2(m["AC"], m["AT"])
	eq3 := computeEQ3(m["VC"], m["VI"], m["VA"])
	eq4 := computeEQ4(m["SC"], m["SI"], m["SA"])
	eq5 := e40[eVal]
	eq6 := computeEQ6(m["VC"], m["VI"], m["VA"])
	eq3eq6 := computeEQ3EQ6(eq3, eq6)

	meanScore, ok := lookupMeanScore(eq1, eq2, eq3eq6, eq4, eq5)
	if !ok {
		return 0, fmt.Errorf("cvss40: no score found for MacroVector (%d,%d,%d,%d,%d)", eq1, eq2, eq3eq6, eq4, eq5)
	}

	type eqContrib struct {
		dist  float64
		depth float64
	}

	var contribs []eqContrib

	if nextScore, has := lookupMeanScore(eq1+1, eq2, eq3eq6, eq4, eq5); has {
		d := depthEQ1(eq1, m["AV"], m["PR"], m["UI"])
		if d > 0 {
			contribs = append(contribs, eqContrib{meanScore - nextScore, d})
		}
	}
	if nextScore, has := lookupMeanScore(eq1, eq2+1, eq3eq6, eq4, eq5); has {
		d := depthEQ2(eq2, m["AC"], m["AT"])
		if d > 0 {
			contribs = append(contribs, eqContrib{meanScore - nextScore, d})
		}
	}
	if nextScore, has := lookupMeanScore(eq1, eq2, eq3eq6+1, eq4, eq5); has {
		d := depthEQ3EQ6(eq3eq6, m["VC"], m["VI"], m["VA"])
		if d > 0 {
			contribs = append(contribs, eqContrib{meanScore - nextScore, d})
		}
	}
	if nextScore, has := lookupMeanScore(eq1, eq2, eq3eq6, eq4+1, eq5); has {
		d := depthEQ4(eq4, m["SC"], m["SI"], m["SA"])
		if d > 0 {
			contribs = append(contribs, eqContrib{meanScore - nextScore, d})
		}
	}
	if nextScore, has := lookupMeanScore(eq1, eq2, eq3eq6, eq4, eq5+1); has {
		d := float64(eq5) / 2.0
		if d > 0 {
			contribs = append(contribs, eqContrib{meanScore - nextScore, d})
		}
	}

	if len(contribs) == 0 {
		return meanScore, nil
	}

	n := float64(len(contribs))
	weightedSum := 0.0
	for _, c := range contribs {
		weightedSum += c.dist * c.depth
	}
	value := meanScore - weightedSum/n

	value = math.Max(0.0, math.Min(10.0, value))
	value = math.Round(value*10) / 10
	return value, nil
}

func depthEQ1(level int, av, pr, ui string) float64 {
	raw := av40[av] + pr40[pr] + ui40[ui]
	switch level {
	case 0:
		return 0
	case 1:
		const minDepth, maxDepth = 1, 4
		if raw <= minDepth {
			return 0
		}
		return float64(raw-minDepth) / float64(maxDepth-minDepth)
	case 2:
		const minDepth, maxDepth = 3, 7
		if raw <= minDepth {
			return 0
		}
		return float64(raw-minDepth) / float64(maxDepth-minDepth)
	}
	return 0
}

func depthEQ2(level int, ac, at string) float64 {
	raw := ac40[ac] + at40[at]
	switch level {
	case 0:
		return 0
	case 1:
		const minDepth, maxDepth = 1, 2
		if raw <= minDepth {
			return 0
		}
		return float64(raw-minDepth) / float64(maxDepth-minDepth)
	}
	return 0
}

func depthEQ3EQ6(level int, vc, vi, va string) float64 {
	raw := cia40[vc] + cia40[vi] + cia40[va]
	switch level {
	case 0:
		const minDepth, maxDepth = 0, 2
		if raw <= minDepth {
			return 0
		}
		return float64(raw-minDepth) / float64(maxDepth-minDepth)
	case 1:
		const minDepth, maxDepth = 1, 4
		if raw <= minDepth {
			return 0
		}
		return float64(raw-minDepth) / float64(maxDepth-minDepth)
	case 4:
		const minDepth, maxDepth = 3, 6
		if raw <= minDepth {
			return 0
		}
		return float64(raw-minDepth) / float64(maxDepth-minDepth)
	default:
		return 0
	}
}

func depthEQ4(level int, sc, si, sa string) float64 {
	scOrd := cia40[sc]
	siOrd := map[string]int{"H": 0, "S": 0, "L": 1, "N": 2}[si]
	saOrd := map[string]int{"H": 0, "S": 0, "L": 1, "N": 2}[sa]
	raw := scOrd + siOrd + saOrd
	switch level {
	case 1:
		const minDepth, maxDepth = 0, 4
		if raw <= minDepth {
			return 0
		}
		return float64(raw-minDepth) / float64(maxDepth-minDepth)
	case 2:
		const minDepth, maxDepth = 3, 6
		if raw < minDepth {
			raw = minDepth
		}
		if raw <= minDepth {
			return 0
		}
		return float64(raw-minDepth) / float64(maxDepth-minDepth)
	}
	return 0
}

func computeEQ1(av, pr, ui string) int {
	if av == "N" && pr == "N" && ui == "N" {
		return 0
	}
	if av != "P" && (av == "N" || pr == "N" || ui == "N") {
		return 1
	}
	return 2
}

func computeEQ2(ac, at string) int {
	if ac == "L" && at == "N" {
		return 0
	}
	return 1
}

func computeEQ3(vc, vi, va string) int {
	if vc == "H" && vi == "H" {
		return 0
	}
	if vc == "H" || vi == "H" || va == "H" {
		return 1
	}
	return 2
}

func computeEQ4(sc, si, sa string) int {
	if sc == "H" || si == "H" || sa == "H" {
		return 1
	}
	return 2
}

func computeEQ6(vc, vi, va string) int {
	if vc == "H" || vi == "H" || va == "H" {
		return 0
	}
	return 1
}

func computeEQ3EQ6(eq3, eq6 int) int {
	switch {
	case eq3 == 0 && eq6 == 0:
		return 0
	case (eq3 == 0 && eq6 == 1) || (eq3 == 1 && eq6 == 0):
		return 1
	case eq3 == 1 && eq6 == 1:
		return 2
	case eq3 == 2 && eq6 == 0:
		return 3
	default:
		return 4
	}
}
