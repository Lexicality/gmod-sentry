# Sentry integration for Garry's Mod

Track errors as they happen on your server, find out which workshop addon is making your players quit and track bugs without having to rely on user reports.

## Requirements
- A server host that lets you install binary modules
- [gmsv_luaerror.dll][luaerror] Installed in your server's lua/bin folder
- An account on [sentry.io][sentry] or a [custom sentry installation][custom_sentry]

## Setup
1. [Download][luaerror_dl] and install the correct version of luaerror from your server (eg gmsv_luaerror_linux.dll)
2. Set up a project in Sentry
3. [Find your DSN][sentry_dsn]
4. Upload sentry.lua to `lua/includes/modules` on the server
5. Create `lua/autorun/server/sentry.lua` on the server with the contents
   ```lua
   require( "sentry" )
   sentry.Setup( "YOUR DSN HERE", { server_name = "SHORT NAME FOR SERVER" } )
   ```
6. Start collecting errors!

## Customisation
### sentry.Setup()
You can pass a number of fields to [`sentry.Setup`](https://lexicality.github.io/gmod-sentry#Setup):
- `server_name`: Tags your server in the sentry UI. If you have more than one server, this is useful for filtering between them. If you don't set it, your server's public hostname will be used.
- `environment`: Used for setting up [Environments][sentry_env] on sentry. Not very useful if you don't run a testing server.
- `release`: Used by the [Releases][sentry_rel] feature in Sentry.
- `tags`: Any additional tags you want every error from this server to be tagged with
- `no_detour`: If you don't want the module to override certain functions (because you've already overriden them) then pass them in here.

#### Example:
```lua
sentry.Setup(
	"https://key@sentry.io/1337",
	{
		server_name = "server 7",
		environment = "production",
		release = "v23",
		tags = { foo = "bar" },
		no_detour = { "hook.Call" },
	}
)
```

### Transactions
By default this module will detour a number of Lua entry points to attempt to instrument as many things with useful transaction names as possible.

This means your errors will be tagged with things such as `hook/PlayerInitialSpawn/DarkRP_DoorData` or `net/GModSave`, but you may wish to use your own names for functions. You can use [`sentry.ExecuteInTransaction`](https://lexicality.github.io/gmod-sentry#ExecuteInTransaction) to do this.

#### Example:
```lua
function DoDatabaseSave( ply )
	-- snip
end
hook.Add( "PlayerDisconnected", "Save Player Data", function( ply )
	sentry.ExecuteInTransaction( "My Save System", DoDatabaseSave, ply )
end)
```

## Documentation
A generated [LDoc][ldoc] file is available at [https://lexicality.github.io/gmod-sentry](https://lexicality.github.io/gmod-sentry)


[luaerror]: https://github.com/danielga/gm_luaerror/
[luaerror_dl]: https://github.com/danielga/gm_luaerror/releases
[sentry]: https://sentry.io/
[sentry_env]: https://docs.sentry.io/learn/environments/
[sentry_rel]: https://docs.sentry.io/learn/releases/
[custom_sentry]: https://docs.sentry.io/server/installation/
[sentry_dsn]: https://docs.sentry.io/quickstart/#about-the-dsn
[ldoc]: https://stevedonovan.github.io/ldoc/
