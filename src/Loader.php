<?php

declare(strict_types=1);

namespace cooldogedev\WDPELoginExtras;

use Closure;
use JsonMapper;
use JsonMapper_Exception;
use pocketmine\event\Listener;
use pocketmine\event\player\PlayerCreationEvent;
use pocketmine\event\player\PlayerLoginEvent;
use pocketmine\event\player\PlayerQuitEvent;
use pocketmine\event\server\DataPacketReceiveEvent;
use pocketmine\network\mcpe\JwtException;
use pocketmine\network\mcpe\JwtUtils;
use pocketmine\network\mcpe\protocol\LoginPacket;
use pocketmine\player\PlayerInfo;
use pocketmine\player\XboxLivePlayerInfo;
use pocketmine\plugin\PluginBase;
use pocketmine\utils\TextFormat;
use ReflectionClass;

final class Loader extends PluginBase implements Listener
{
    private array $xuidMap = [];

    protected function onEnable(): void
    {
        $this->getServer()->getPluginManager()->registerEvents($this, $this);
    }

    /**
     * @priority LOWEST
     */
    public function onDataPacketReceive(DataPacketReceiveEvent $event): void
    {
        $origin = $event->getOrigin();
        $packet = $event->getPacket();

        if ($packet instanceof LoginPacket) {
            try {
                [, $claim,] = JwtUtils::parse($packet->clientDataJwt);
            } catch (JwtException) {
                $origin->disconnect("Invalid JWT");
                return;
            }

            $mapper = new JsonMapper();
            $mapper->bEnforceMapType = false;
            $mapper->bExceptionOnMissingData = true;
            $mapper->bExceptionOnUndefinedProperty = true;

            try {
                /** @var ClientData $clientData */
                $clientData = $mapper->map($claim, new ClientData());
            } catch (JsonMapper_Exception) {
                $origin->disconnect("Failed to parse JWT");
                return;
            }

            $this->xuidMap[$clientData->Waterdog_IP . ":" . $origin->getPort()] = [$clientData->Waterdog_XUID, $clientData->Waterdog_IP];

            $origin->setHandler(new LoginHandler(
                server: $this->getServer(),
                session: $origin,
                playerInfoConsumer: Closure::bind(function (PlayerInfo $info) use ($origin, $clientData): void {
                    $origin->ip = $clientData->Waterdog_IP;
                    $origin->info = $info;
                    $origin->logger->setPrefix($origin->getLogPrefix());
                    $origin->logger->info("Player: " . TextFormat::AQUA . $info->getUsername() . TextFormat::RESET);
                }, $this, $origin),
                authCallback: Closure::bind(function (bool $isAuthenticated, bool $authRequired, ?string $error, ?string $clientPubKey) use ($origin): void {
                    $origin->setAuthenticationStatus(true, $authRequired, $error, $clientPubKey);
                }, $this, $origin),
            ));
        }
    }

    /**
     * @priority LOWEST
     */
    public function onPlayerCreation(PlayerCreationEvent $event): void
    {
        $networkSession = $event->getNetworkSession();
        $info = $networkSession->getPlayerInfo();
        [$xuid, $ip] = $this->xuidMap[$event->getAddress() . ":" . $event->getPort()] ?? null;

        if ($xuid !== null) {
            $reflection = new ReflectionClass($networkSession);
            $reflection->getProperty("info")?->setValue($networkSession, new XboxLivePlayerInfo($xuid, $info->getUsername(), $info->getUuid(), $info->getSkin(), $info->getLocale(), $info->getExtraData()));
        }
    }

    /**
     * @priority LOWEST
     */
    public function onPlayerLogin(PlayerLoginEvent $event): void
    {
        $player = $event->getPlayer();
        $networkSession = $player->getNetworkSession();

        [$xuid, $ip] = $this->xuidMap[$networkSession->getIp() . ":" . $networkSession->getPort()] ?? null;

        if ($xuid !== null) {
            $class = new ReflectionClass($player);
            $class->getProperty("xuid")->setValue($player, $xuid);

            unset($this->xuidMap[$networkSession->getIp() . ":" . $networkSession->getPort()]);
        }
    }

    /**
     * @priority LOWEST
     */
    public function onPlayerQuit(PlayerQuitEvent $event): void
    {
        $player = $event->getPlayer();
        $networkSession = $player->getNetworkSession();

        unset($this->xuidMap[$networkSession->getIp() . ":" . $networkSession->getPort()]);
    }

    public function onDisable(): void
    {
        $this->xuidMap = [];
    }
}
