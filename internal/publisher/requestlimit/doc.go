// package requestlimit owns each publish or service run's HTTP request budget.
// run owners share one budget across visitor connections. it depends on validated
// limits and wire inputs, never on public URL or service orchestration.
package requestlimit
