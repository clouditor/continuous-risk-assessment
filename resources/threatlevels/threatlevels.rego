package threatlevels

asset_to_max_threatlevel[asset] = maxis {
    asset := all_assets[_]
    paths := [path | input[_].bindings.x[i][_] == asset
                     path := data["attackpaths_and_threatlevels"][i]]
    maxis := max(paths)
}

all_assets[assets] {
	assets := input[_].bindings.x[_][_]
}