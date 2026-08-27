$guardar = $false

# Guardamos ÚNICAMENTE la parte derecha en la variable
$mis_redes = netsh.exe wlan show profile | ForEach-Object {
    $linea = $_.ToString()
    
    if ($linea -match "Perfiles de usuario|User profiles") { 
        $guardar = $true 
    }
    
    # Extraemos solo el elemento [1] (lo que está a la derecha de los dos puntos)
    if ($guardar -and $linea -like "*:*") {
        $linea.Split(':', 2)[1].Trim()
    }
}

foreach ($red in $mis_redes) {
    # Ejecuta netsh y filtra inmediatamente la línea de la contraseña
    $resultado = netsh.exe wlan show profile name="$red" key=clear | Select-String "Contenido de la clave|Key content"
    
    # Si encuentra la línea, la muestra en pantalla
    if ($resultado) {
        Write-Host "Red: $red -> $($resultado.ToString().Trim())"
    }
}