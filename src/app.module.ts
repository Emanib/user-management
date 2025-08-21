import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService   } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { APP_GUARD } from "@nestjs/core";

import { ConfigModule , ConfigService } from '@nestjs/config';
import {
  AuthGuard,
  KeycloakConnectConfig,
  KeycloakConnectModule,
  ResourceGuard,
  RoleGuard,
} from "nest-keycloak-connect";

@Module({
  imports: [    ConfigModule.forRoot({ isGlobal: true }),PrismaModule, AuthModule, UsersModule,
       KeycloakConnectModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService): KeycloakConnectConfig => ({
        authServerUrl: configService.get("KC_AUTH_SERVER_URL"),
        realm: configService.get("KC_REALM"),
        clientId: configService.get("KC_CLIENT_ID"),
        secret: configService.get<string>("KC_SECRET") || "",
        useNestLogger: true,
      }),
    }),
  ],


  controllers: [AppController],
  providers: [AppService,    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
     {
      provide: APP_GUARD,
      useClass: ResourceGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RoleGuard,
    },
  ],
})
export class AppModule {}
