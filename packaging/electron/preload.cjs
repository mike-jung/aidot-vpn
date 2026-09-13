'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('aidotDesktop', {
  state: () => ipcRenderer.invoke('desktop:state'),
  apply: settings => ipcRenderer.invoke('desktop:apply', settings),
  chooseEnv: () => ipcRenderer.invoke('desktop:choose-env'),
  openLogs: () => ipcRenderer.invoke('desktop:logs'),
  createTemplate: () => ipcRenderer.invoke('desktop:template')
});
