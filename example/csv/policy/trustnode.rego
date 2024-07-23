package trustnode

import future.keywords.every
default trust_node := false

trust_node {
   allowed_node(input.trust_node)
}

allowed_node(node) {
	node.tee.csv_measurement == "56849ed2f9b7380453de74a9587883ec125288241e90f6989b9992b6d9beaf64"
	every d in node.trust_device {
		allowed_device(d)
	}
}
