import { IsNotEmpty, IsString } from 'class-validator';

export class RefreshSessionDto {
  @IsString()
  @IsNotEmpty()
  session_id: string;

  @IsString()
  @IsNotEmpty()
  refresh_token: string;
}
