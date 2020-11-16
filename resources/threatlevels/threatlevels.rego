package threatlevels

all_assets[assets] {
	assets := input[_].bindings.x[_][_]
}

max_threatlevel(asset, protection_goal) = res {
    paths := { path | input[_].bindings.x[i][_] == asset
    				  split(i, "_")[1] == protection_goal
    				  path := i}
    levels := { level | paths[j]
    				    level := data["attackpaths_and_threatlevels"][j]}
    res := max(levels)                
} else = 0 {
	paths := { path | input[_].bindings.x[i][_] == asset
    				  split(i, "_")[1] == protection_goal
    				  path := i}
    levels := { level | paths[j]
    				    level := data["attackpaths_and_threatlevels"][j]}
    count(levels) == 0
}

impact(asset, protection_goal) = impact_value {
	impact_value := data.asset_impacts[asset][protection_goal]
}

asset_goals_to_impacts[asset_goal_impact] {
	asset_goal_impact := {
    	all_assets[i]: {
        	"confidentiality": impact(all_assets[i], "confidentiality"),
			"integrity": impact(all_assets[i], "integrity"),
        	"availability": impact(all_assets[i], "availability"),
        }
    }	
}

asset_goals_to_risks[risks] {
	risks := {
    	all_assets[i]: {
            "confidentiality": risk_calculation(
                max_threatlevel(all_assets[i], "confidentiality"),
                impact(all_assets[i], "confidentiality"),
            ),
            "integrity": risk_calculation(
                max_threatlevel(all_assets[i], "integrity"),
                impact(all_assets[i], "integrity"),
            ),
            "availability": risk_calculation(
                max_threatlevel(all_assets[i], "availability"),
                impact(all_assets[i], "availability"),
            )
       	}
     }
}

impact(asset, protection_goal) = impact_value {
	impact_value := data.asset_impacts[asset][protection_goal]
} else = 0 {
	not data.asset_impacts[asset]
} else = 0 {
	not data.asset_impacts[asset][protection_goal]
}

risk_calculation(threat, impact) = risk {
	risk := threat * impact
}