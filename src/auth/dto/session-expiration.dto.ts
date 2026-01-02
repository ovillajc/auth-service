import { IsString } from 'class-validator';

export class SessionExpirationDto {
  @IsString()
  session_id: string;
}
