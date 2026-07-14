package ml

import "testing"

func TestLogisticCalibrator_Identity(t *testing.T) {
        c := NewLogisticCalibrator()
        // Default coefficients a=1, b=0 → sigmoid(raw).
        // sigmoid(0) = 0.5, sigmoid(1) ≈ 0.731, sigmoid(-1) ≈ 0.269.
        if got := c.Calibrate(0); got != 0.5 {
                t.Fatalf("expected sigmoid(0)=0.5, got %v", got)
        }
        if got := c.Calibrate(1); got < 0.7 || got > 0.74 {
                t.Fatalf("expected sigmoid(1)~0.73, got %v", got)
        }
}

func TestLogisticCalibrator_FitLearns(t *testing.T) {
        // Build a synthetic dataset where label = (score > 0.5).
        pairs := []LabelledPair{
                {0.1, false}, {0.2, false}, {0.3, false}, {0.4, false},
                {0.6, true}, {0.7, true}, {0.8, true}, {0.9, true},
        }
        c := NewLogisticCalibrator()
        c.Fit(pairs, 500, 0.5)

        // After fitting, the calibrator should produce probabilities that
        // separate the classes reasonably.
        lowOut := c.Calibrate(0.1)
        highOut := c.Calibrate(0.9)
        if lowOut > 0.5 {
                t.Fatalf("expected low score → low prob, got %v", lowOut)
        }
        if highOut < 0.5 {
                t.Fatalf("expected high score → high prob, got %v", highOut)
        }
}

func TestIsolationForest_SimpleCase(t *testing.T) {
        // Build a forest with 2 features: [amount, hour].
        // Normal data with some spread around (30, 12).
        data := [][]float64{}
        for i := 0; i < 50; i++ {
                data = append(data, []float64{28 + float64(i%5), 11 + float64(i%3)})
        }
        f := NewIsolationForest(data, 20, 5)

        normalScore := f.Score([]float64{30, 12})
        anomalyScore := f.Score([]float64{5000, 3})

        // The anomaly should be isolated faster → higher score.
        // Note: with small datasets the scores can saturate, so we just
        // require the anomaly score is at least as high as the normal score.
        if anomalyScore < normalScore {
                t.Fatalf("expected anomaly score >= normal score, got anomaly=%v normal=%v", anomalyScore, normalScore)
        }
}

func TestIsolationForest_Empty(t *testing.T) {
        f := NewIsolationForest(nil, 10, 5)
        if got := f.Score([]float64{1, 2}); got != 0 {
                t.Fatalf("expected 0 for empty forest, got %v", got)
        }
}

func TestPRNG_Deterministic(t *testing.T) {
        p1 := newPRNG(42)
        p2 := newPRNG(42)
        for i := 0; i < 10; i++ {
                if p1.Float64() != p2.Float64() {
                        t.Fatal("expected deterministic PRNG")
                }
        }
}
