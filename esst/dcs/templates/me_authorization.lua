local base = _G

module('me_authorization')

local require       	= base.require
local pairs         	= base.pairs
local table         	= base.table
local math          	= base.math
local loadfile      	= base.loadfile
local setfenv       	= base.setfenv
local string        	= base.string
local assert        	= base.assert
local io            	= base.io
local loadstring    	= base.loadstring
local print         	= base.print
local os            	= base.os

local i18n 				= require('i18n')
local U                 = require('me_utilities')
local DialogLoader      = require('DialogLoader')
local MsgWindow			= require('MsgWindow')
local Modulesmanager    = require('me_modulesmanager')
local DcsWeb            = require('DcsWeb')
local panel_waitDsbweb  = require('me_waitDsbweb')
local lfs               = require('lfs')
local S 				= require('Serializer')
local Tools 			= require('tools')
local module_updater    = require('me_updater')

i18n.setup(_M)

cdata =
{
    IncorrectLoginOrPassword    = _("Incorrect login or password."),
    noInternet                  = _("No internet connection."),
    InternalServerError         = _("Internal Server Error."),
    serialConflict              = _("Invalid serial number."),
    authorization               = _("Authorization"),
    Login                       = _("Login"),
    Password                    = _("Password"),
    Savepassword                = _("Save password"),
    Cancel                      = _("OFFLINE"),
    Connect                     = _("CONNECTION"),
    Register                    = _("Register"),
    Restore                     = _("Forgot your password?"),
    LogintoDigital              = _("Connection to DCS"),
    autojoin                    = _("Auto Login"),
    ErrorLogin                  = _("Error Login"),
    DCSuser                     = _("DCS user"),
    Registration                = _("Registration"),
    error_email                 = _("This e-mail address already used"),
    error_login                 = _("User with this login already exists"),
    error_password              = _("Incorrect password confirmation"),
    error_code                  = _("Code is entered incorrectly"),

    Email                       = _("E-mail"),
    Repeatpassword              = _("Repeat password"),
    Typesymbols                 = _("Typesymbols"),



}

local bCreated = false
local autojoin = nil
local bAuthSuccess = false
local Login = nil
local window

-------------------------------------------------------------------------------
--
function create()
    window = DialogLoader.spawnDialogFromFile(base.dialogsDir .. 'login_dialog_new.dlg', cdata)

    local main_w = base.main_w
    local main_h = base.main_h

    local box = window.Box

    local win_w
    local win_h
    win_w, win_h = 350, 300   --box:getSize()

    window:setBounds(0, 0, main_w, main_h)
    box:setBounds((main_w - win_w)/2, (main_h - win_h)/2, 650, 650)

    bCancel         = box.bCancel
    tgiLogin        = box.tgiLogin
    tgiRegistration = box.tgiRegistration
    pLogin          = box.pLogin
    eLogin          = pLogin.eLogin
    ePassword       = pLogin.ePassword
    bConnect        = pLogin.bConnect
    bRestore        = pLogin.bRestore
  --  bRegister   = pLogin.bRegister
    cbSave          = pLogin.cbSave
    cbAutojoin      = pLogin.cbAutojoin
    sError          = pLogin.sError
    eError          = pLogin.eError

    pRegistration   = box.pRegistration

    pRegistration:setBounds(0, 92, 650, 650)
    sError:setVisible(false)
    eError:setVisible(false)


    cbAutojoin.onChange = cbAutojoin_onChange

    eLogin:addKeyUpCallback(keyUpCallback)
    ePassword:addKeyUpCallback(keyUpCallback)
 --   cbAutojoin:setVisible(false)

    tgiLogin.onShow         = onChange_tgiLogin
    tgiRegistration.onShow  = onChange_tgiRegistration

    bCancel.onChange = onChange_Cancel
    bConnect.onChange = onChange_Connect
    bRestore.onChange = onChange_Restore
 --   bRegister.onChange = onChange_Register

    window:addHotKeyCallback('escape'	, onChange_Cancel)
    window:addHotKeyCallback('return'	, onChange_Connect)
    window:addHotKeyCallback('space'	, onKey_space)

    bCreated = true
end

-------------------------------------------------------------------------------
--
function getLogin()
    return Login
end

-------------------------------------------------------------------------------
--
function isAutorization()
    return bAuthSuccess
end

-------------------------------------------------------------------------------
--
function keyUpCallback(self)
    sError:setVisible(false)
    eError:setVisible(false)
end

-------------------------------------------------------------------------------
--
function cbAutojoin_onChange(self)
    autojoin = cbAutojoin:getState()
end

-------------------------------------------------------------------------------
--
function onChange_tgiLogin(self)
    pLogin:setVisible(true)
    pRegistration:setVisible(false)
end

-------------------------------------------------------------------------------
--
function onChange_tgiRegistration(self)
    pLogin:setVisible(false)
    pRegistration:setVisible(true)
end


-------------------------------------------------------------------------------
--
function show(b, a_callbackSetAuth)
    callbackSetAuth = a_callbackSetAuth
    if bCreated == false then
        create()
    end

    if b == true then
        local saveLogin = {
            master_login = DcsWeb.get_username(),
            master_password = DcsWeb.get_password()
        }
        cbSave:setState(DcsWeb.get_savepw())
        if (saveLogin ~= nil) then
            if (saveLogin.master_login ~= nil) and (saveLogin.master_login ~= "") then
                eLogin:setText(saveLogin.master_login)
                if (saveLogin.master_password ~= nil) and (saveLogin.master_password ~= "") then
                    ePassword:setText(saveLogin.master_password)
                    if autojoin == nil then
                        autojoin = loadAutojoin()
                    end
                    cbAutojoin:setState(autojoin)
                else
                    ePassword:setText("")
                end
            else
                eLogin:setText("")
                ePassword:setText("")
            end
        else
            eLogin:setText("")
            ePassword:setText("")
        end
    end
    window:setVisible(b)
end

-------------------------------------------------------------------------------
--
function openAutorization(a_callbackSetAuth)
    if DcsWeb.get_status('dcs:login') == 200 then
        bAuthSuccess = true
        Login = DcsWeb.get_username()
        if a_callbackSetAuth then
            a_callbackSetAuth(true)
        end
        return
    end
    if autojoin == nil then
        autojoin = loadAutojoin()
    end
    if autojoin == true then
        callbackSetAuth = a_callbackSetAuth
        silentAutorization()
    else
        show(true,a_callbackSetAuth)
    end
end

-------------------------------------------------------------------------------
--
function silentAutorization()
    local saveLogin = {
        master_login = DcsWeb.get_username(),
        master_password = DcsWeb.get_password()
    }
    if (saveLogin ~= nil)
        and (saveLogin.master_login ~= nil) and (saveLogin.master_password ~= nil)
        and (saveLogin.master_login ~= "") and (saveLogin.master_password ~= "") then

        Login = saveLogin.master_login
        autorization(saveLogin.master_login, saveLogin.master_password, true)
    else
        bAuthSuccess = false
        if callbackSetAuth then
            callbackSetAuth(false)
        end
    end
end

-------------------------------------------------------------------------------
--
function onKey_space()
base.print("---getFocused--",cbSave:getFocused(),cbAutojoin:getFocused(),cbSave:getState(),cbAutojoin:getState() )
    if cbSave:getFocused() == true then
        cbSave:setState(not cbSave:getState())
    end

    if cbAutojoin:getFocused() == true then
        cbAutojoin:setState(not cbAutojoin:getState())
        cbSave:setState(not cbSave:getState())
    end
end

-------------------------------------------------------------------------------
--
function onChange_Connect()
    Login = nil

    Login           =   eLogin:getText()
    local Password  =   ePassword:getText()
    local SavePW    =   cbSave:getState()

    local res = autorization(Login, Password, SavePW)
end

-------------------------------------------------------------------------------
--
function autorization(a_login, a_password, b_savepw)
    if bCreated == false then
        create()
    end
    panel_waitDsbweb.show(true)
    DcsWeb.send_request('dcs:login', { username = a_login, password = a_password, savepw = base.tostring(b_savepw)--[[, savepw = b_savepw]]})
    panel_waitDsbweb.startWait(verifyStatusLogin, end_autorization)
end

-------------------------------------------------------------------------------
--
function loadAutojoin()
    local tbl = Tools.safeDoFile(lfs.writedir()..'MissionEditor/optionsLogin.lua')
    local opt
    if tbl then
        opt = tbl.optionsLogin
    end
    if opt then
        return opt.autojoin or false
    end
    return false
end

-------------------------------------------------------------------------------
--
function saveAutojoin(a_autojoin)
    local f = assert(io.open(lfs.writedir() .. 'MissionEditor/optionsLogin.lua', 'w'))
    if f then
        local sr = S.new(f)
        sr:serialize_simple2('optionsLogin', {autojoin = a_autojoin})
        f:close()
    end
end

-------------------------------------------------------------------------------
--
function verifyStatusLogin()
    local status = DcsWeb.get_status('dcs:login')

    if status ~= 102 then
        return true, status
    end
    return false
end

-------------------------------------------------------------------------------
--
function end_autorization(status)
    if (status == 200) then
        bAuthSuccess = true
        if callbackSetAuth then
            callbackSetAuth(true)
        end
        saveAutojoin(autojoin)
        show(false)

        -- DEDICATED CODE ADD THIS --
        local net = require('net')

        local mpConfig = Tools.safeDoFile(lfs.writedir() .. 'Config/serverSettings.lua', false)
        local dediConfig = Tools.safeDoFile(lfs.writedir() .. 'Config/dedicated.lua', false)

         if dediConfig and dediConfig.dedicated ~= nil and dediConfig.dedicated["enabled"] == true then

           net.set_name('{{ server_name }}')
           net.start_server(mpConfig.cfg)
           net.log("Starting Dedicated Server...")
        end
        -- END DEDICATED CODE --
    else
        saveAutojoin(false)
        bAuthSuccess = false
        if callbackSetAuth then
            callbackSetAuth(false)
        end
        if sError then
            sError:setVisible(true)
            eError:setVisible(true)
            eError:setText("")
            if status == 503 then
                sError:setText(cdata.noInternet)
            elseif status == 500 then
                sError:setText(cdata.InternalServerError)
            elseif status == 409 then
                local login_data = DcsWeb.get_data('dcs:login')
                if login_data then
                    local data = module_updater.decodeJSON(login_data)
                    sError:setText(cdata.serialConflict)
                    local text = ""
                    if data and data.rejected_keys then
                        for k,v in base.pairs(data.rejected_keys) do
                            text = text..v.."\n"
                        end
                    end
                    eError:setText(text)
                else
                    sError:setText(cdata.serialConflict)
                end
            else
                sError:setText(cdata.IncorrectLoginOrPassword)
            end
        end
    end
end

-------------------------------------------------------------------------------
--
function logout(a_callbackSetAuth)
    callbackSetAuth = a_callbackSetAuth

    panel_waitDsbweb.show(true)
    DcsWeb.send_request('dcs:logout')

    panel_waitDsbweb.startWait(verifyStatusLogout, end_logout)
end


-------------------------------------------------------------------------------
--
function verifyStatusLogout()
    local status = DcsWeb.get_status('dcs:logout')

    if status ~= 102 then
        return true, status
    end
    return false
end

-------------------------------------------------------------------------------
--
function end_logout(status)
    if (status == 200) then
        Login = nil
        bAuthSuccess = false

        local res = DcsWeb.logout()
        if callbackSetAuth then
            callbackSetAuth(false)
        end
    else

        MsgWindow.error(_("Error logout"), _("LOGOUT"), 'OK'):show()
    end
end

-------------------------------------------------------------------------------
--
function onChange_Cancel()
    if callbackSetAuth then
        callbackSetAuth(false)
    end
    --logout()
    show(false)
end

-------------------------------------------------------------------------------
--
function onChange_Restore()
    local url = DcsWeb.make_auth_url('dcs:restore_url')
    local cmd = "start ".."\"\" \""..url.."\""
    os.execute(cmd)
end

-------------------------------------------------------------------------------
--
function onChange_Register()
    local url = DcsWeb.make_auth_url('dcs:signup_url')
    local cmd = "start ".."\"\" \""..url.."\""
    os.execute(cmd)
end
