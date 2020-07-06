package gin_authn


func toStringSlice(ivalues interface{}) []string {
	svalues := ivalues.([]interface{})
	res := make([]string, len(svalues))
	for i, v := range svalues {
		res[i] = v.(string)
	}
	return res
}

func containsAll(src []string, vals []string) bool {
	if len(vals) == 0 {
		return true
	}

	for _, v := range vals {
		if !contains(src, v) {
			return false
		}
	}

	return true
}

func contains(src []string, val string) bool {
	for _, e := range src {
		if e == val {
			return true
		}
	}
	return false
}

