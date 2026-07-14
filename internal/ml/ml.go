// Package ml implements a lightweight model calibration layer on top of the
// statistical detectors.
//
// The ensemble produces a raw score in [0, 1] by weighted voting. In practice
// that score is well-correlated with fraud but not perfectly calibrated — a
// raw score of 0.7 doesn't necessarily mean "70% probability of fraud".
// Calibration maps the raw score onto a true probability using logistic
// regression (Platt scaling), fitted on the labelled seed dataset.
//
// This package also implements a simple Isolation Forest-style anomaly
// detector that flags transactions with unusual feature combinations. The
// IF score is combined with the calibrated ensemble score via a final
// logistic regression to produce the final calibrated probability.
//
// Everything is implemented in pure Go (no external ML deps) so the binary
// stays small and deployable.
package ml

import (
	"math"
	"sync"
)

// LogisticCalibrator applies Platt scaling: maps a raw score in [0, 1] to
// a calibrated probability via sigmoid(a * x + b). The coefficients a and b
// are fitted on labelled data (see Fit).
type LogisticCalibrator struct {
	mu sync.RWMutex
	a  float64 // slope
	b  float64 // intercept
}

// NewLogisticCalibrator builds a calibrator with identity defaults
// (a=1, b=0 — output equals input).
func NewLogisticCalibrator() *LogisticCalibrator {
	return &LogisticCalibrator{a: 1, b: 0}
}

// Fit runs a small batch of gradient descent to find (a, b) that minimises
// log-loss on the labelled pairs. Convergence is fast because we only have
// two parameters; 500 iterations of plain SGD with lr=0.1 is enough.
func (c *LogisticCalibrator) Fit(pairs []LabelledPair, iterations int, lr float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	a, b := 1.0, 0.0
	for i := 0; i < iterations; i++ {
		var gradA, gradB float64
		for _, p := range pairs {
			z := a*p.Score + b
			pred := sigmoid(z)
			err := pred - float64(labelToFloat(p.Label))
			gradA += err * p.Score
			gradB += err
		}
		n := float64(len(pairs))
		a -= lr * gradA / n
		b -= lr * gradB / n
	}
	c.a = a
	c.b = b
}

// Calibrate maps a raw score to a calibrated probability.
func (c *LogisticCalibrator) Calibrate(raw float64) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return sigmoid(c.a*raw + c.b)
}

// Coefficients returns the fitted (a, b). Useful for introspection / tests.
func (c *LogisticCalibrator) Coefficients() (a, b float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.a, c.b
}

// LabelledPair is one training example for the calibrator.
type LabelledPair struct {
	Score float64 // raw ensemble score
	Label bool    // true = fraud
}

func labelToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func sigmoid(z float64) float64 {
	if z < -700 {
		return 0
	}
	if z > 700 {
		return 1
	}
	return 1.0 / (1.0 + math.Exp(-z))
}

// IsolationForest is a simple isolation forest for anomaly detection.
//
// Each tree recursively partitions the feature space by picking a random
// feature and a random split point. Anomalous points require fewer splits
// to isolate, so their path length is shorter. The anomaly score is
// s(x, n) = 2^(-E(h(x)) / c(n)) where c(n) ≈ 2*ln(n-1) - 0.5772.
//
// This implementation uses 2 features: normalized amount (log-scaled) and
// hour-of-day. More features can be added behind the same interface.
type IsolationForest struct {
	trees []iTree
}

// iTree is a single isolation tree.
type iTree struct {
	feature int // 0 = amount, 1 = hour
	split   float64
	left    *iTree
	right   *iTree
	height  int
}

// NewIsolationForest builds `nTrees` trees of max depth `maxDepth` on the
// given feature vectors.
func NewIsolationForest(features [][]float64, nTrees, maxDepth int) *IsolationForest {
	if len(features) == 0 {
		return &IsolationForest{}
	}
	rng := newPRNG(42)
	f := &IsolationForest{}
	for i := 0; i < nTrees; i++ {
		// Sample a subset (size = 256 is standard, but we use all data here).
		f.trees = append(f.trees, buildTree(features, maxDepth, 0, rng))
	}
	return f
}

// Score returns the anomaly score for a feature vector in [0, 1].
// Higher = more anomalous.
func (f *IsolationForest) Score(x []float64) float64 {
	if len(f.trees) == 0 {
		return 0
	}
	var sumPath float64
	for _, t := range f.trees {
		sumPath += pathLength(t, x, 0)
	}
	avg := sumPath / float64(len(f.trees))
	// c(n) for n ≈ 256 is ~5.04; we use a fixed normalisation.
	c := 5.04
	return math.Pow(2, -avg/c)
}

func buildTree(data [][]float64, maxDepth, depth int, rng *prng) iTree {
	if depth >= maxDepth || len(data) <= 1 {
		return iTree{height: depth}
	}
	feature := rng.Intn(len(data[0]))
	// Pick a split point between min and max of the chosen feature.
	min, max := math.MaxFloat64, -math.MaxFloat64
	for _, row := range data {
		v := row[feature]
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	if min == max {
		return iTree{height: depth}
	}
	split := min + rng.Float64()*(max-min)

	var left, right [][]float64
	for _, row := range data {
		if row[feature] < split {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}

	t := iTree{feature: feature, split: split, height: depth}
	if len(left) > 0 {
		l := buildTree(left, maxDepth, depth+1, rng)
		t.left = &l
	}
	if len(right) > 0 {
		r := buildTree(right, maxDepth, depth+1, rng)
		t.right = &r
	}
	return t
}

func pathLength(t iTree, x []float64, depth int) float64 {
	if t.left == nil && t.right == nil {
		return float64(depth)
	}
	if x[t.feature] < t.split {
		if t.left != nil {
			return pathLength(*t.left, x, depth+1)
		}
	} else {
		if t.right != nil {
			return pathLength(*t.right, x, depth+1)
		}
	}
	return float64(depth)
}

// prng is a tiny linear-congruential PRNG (avoids pulling in math/rand for
// this small package). NOT cryptographically secure — fine for IF training.
type prng struct {
	state uint64
}

func newPRNG(seed uint64) *prng { return &prng{state: seed} }

func (p *prng) Next() uint64 {
	p.state = p.state*6364136223846793005 + 1442695040888963407
	return p.state
}

func (p *prng) Float64() float64 {
	return float64(p.Next()>>11) / float64(1<<53)
}

func (p *prng) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(p.Next() % uint64(n))
}
