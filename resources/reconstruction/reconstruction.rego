package reconstruction

asset_to_paths[asset] = paths {
    asset := all_assets[_]
    paths := [path | input[_].bindings.x[i][_] == asset
                     path := i]
}

all_assets[assets] {
	assets := input[_].bindings.x[_][_]
}
