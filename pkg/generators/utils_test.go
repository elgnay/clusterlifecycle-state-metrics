// Copyright (c) 2020 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package generators

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kube-state-metrics/pkg/metric"
)

func Test_BuildStatusConditionMetricFamily(t *testing.T) {
	tests := []struct {
		name               string
		conditions         []metav1.Condition
		keys               []string
		values             []string
		requiredConditions []string
		expected           metric.Family
	}{
		{
			name:     "no condition",
			expected: metric.Family{},
		},
		{
			name: "without fixed key/values",
			conditions: []metav1.Condition{
				{
					Type:   "Available",
					Status: metav1.ConditionFalse,
				},
			},
			expected: metric.Family{
				Metrics: []*metric.Metric{
					newMetric(1).
						withLabel("condition", "Available").
						withLabel("status", "false").
						build(),
				},
			},
		},
		{
			name: "with fixed key/values",
			conditions: []metav1.Condition{
				{
					Type:   "Available",
					Status: metav1.ConditionTrue,
				},
			},
			keys:   []string{"name"},
			values: []string{"cluster1"},
			expected: metric.Family{
				Metrics: []*metric.Metric{
					newMetric(1).
						withLabel("name", "cluster1").
						withLabel("condition", "Available").
						withLabel("status", "true").
						build(),
				},
			},
		},
		{
			name: "with required conditions",
			conditions: []metav1.Condition{
				{
					Type:   "Available",
					Status: metav1.ConditionUnknown,
				},
			},
			requiredConditions: []string{"Applied"},
			keys:               []string{"name"},
			values:             []string{"cluster1"},
			expected: metric.Family{
				Metrics: []*metric.Metric{
					newMetric(1).
						withLabel("name", "cluster1").
						withLabel("condition", "Available").
						withLabel("status", "unknown").
						build(),
					newMetric(1).
						withLabel("name", "cluster1").
						withLabel("condition", "Applied").
						withLabel("status", "unknown").
						build(),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := BuildStatusConditionMetricFamily(tt.conditions, tt.keys, tt.values, tt.requiredConditions)
			if !reflect.DeepEqual(tt.expected, actual) {
				t.Errorf("want %v but got %v", string(tt.expected.ByteSlice()), string(actual.ByteSlice()))
			}
		})
	}
}

type metricBuilder struct {
	metric metric.Metric
}

func newMetric(value float64) *metricBuilder {
	return &metricBuilder{
		metric: metric.Metric{
			Value: value,
		},
	}
}

func (b *metricBuilder) withLabel(key, value string) *metricBuilder {
	b.metric.LabelKeys = append(b.metric.LabelKeys, key)
	b.metric.LabelValues = append(b.metric.LabelValues, value)
	return b
}

func (b *metricBuilder) build() *metric.Metric {
	return &b.metric
}
